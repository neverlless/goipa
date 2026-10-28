// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestStageUserAdd_OmitsEmpty(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"result":{"uid":["eve"]},"value":"eve","summary":""}`))
	if _, err := c.StageUserAdd(&ipa.User{Username: "eve", First: "Eve", Last: "E"}); err != nil {
		t.Fatal(err)
	}
	opts := f.Calls()[0].Options
	for _, k := range []string{"mail", "homedirectory", "telephonenumber"} {
		if _, ok := opts[k]; ok {
			t.Errorf("option %q sent: %v", k, opts)
		}
	}
	if opts["givenname"] != "Eve" {
		t.Errorf("givenname = %v", opts["givenname"])
	}
}

func TestStageUserAdd_Required(t *testing.T) {
	_, c := newFake(t)
	_, err := c.StageUserAdd(&ipa.User{Username: "eve", Last: "E"})
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != ipa.CodeRequirement {
		t.Fatalf("err = %v, want *IpaError %d", err, ipa.CodeRequirement)
	}
}

func TestStageUserDelete_NoNames(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if err := c.StageUserDelete(); err == nil {
		t.Error("nil error")
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestStageUserShow_EmptyName(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if _, err := c.StageUserShow(""); err == nil {
		t.Error("nil error")
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestStageUserFind_DoesNotModifyOptions(t *testing.T) {
	_, c := newFake(t)
	opts := ipa.Options{"uid": "x"}
	if _, err := c.StageUserFind(opts); err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 {
		t.Errorf("options modified: %v", opts)
	}
}

func TestStageUserAddWithPassword_SendsUserpassword(t *testing.T) {
	s, c := newFake(t)
	u, err := c.StageUserAddWithPassword(&ipa.User{Username: "eve", First: "Eve", Last: "E"}, "Secret123")
	if err != nil || !u.HasPassword {
		t.Fatalf("add = %+v, %v", u, err)
	}
	call := s.Calls()[0]
	if call.Method != "stageuser_add" || call.Options["userpassword"] != "REDACTED" {
		t.Errorf("call = %+v", call)
	}
	if r, _ := s.StageUser("eve"); r.Password != "Secret123" {
		t.Errorf("server password = %q", r.Password)
	}
}

func TestStageUserAddWithPassword_Validation(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{}`))
	if _, err := c.StageUserAddWithPassword(&ipa.User{Username: "eve"}, ""); err == nil || err.Error() != "ipa: password is required" {
		t.Errorf("err = %v", err)
	}
	if _, err := c.StageUserAddWithPassword(&ipa.User{}, "x"); err == nil || err.Error() != "ipa: username is required" {
		t.Errorf("err = %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestStageUserActivate_KeepsPassword(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.StageUserAddWithPassword(&ipa.User{Username: "eve", First: "Eve", Last: "E"}, "Secret123"); err != nil {
		t.Fatal(err)
	}
	u, err := c.StageUserActivate("eve")
	if err != nil || !u.HasPassword {
		t.Fatalf("activate = %+v, %v", u, err)
	}
	if err := s.Client().RemoteLogin("eve", "Secret123"); !errors.Is(err, ipa.ErrExpiredPassword) {
		t.Errorf("login = %v, want expired password", err)
	}
}

func TestCalls_RedactsPasswords(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.RPC("user_add", []string{"al"}, ipa.Options{"givenname": "A", "sn": "L", "userpassword": "Secret123"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range s.Calls() {
		if strings.Contains(fmt.Sprint(call.Options), "Secret123") {
			t.Errorf("%s leaks: %v", call.Method, call.Options)
		}
	}
	if got := s.Calls()[0].Options["userpassword"]; got != "REDACTED" {
		t.Errorf("user_add userpassword = %v", got)
	}
	if u, _ := s.User("al"); u.Password == "REDACTED" || u.Password == "" {
		t.Errorf("server password = %q", u.Password)
	}
}

func TestUserMod_SetattrPasswordExpiration(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.StageUserAddWithPassword(&ipa.User{Username: "eve", First: "Eve", Last: "E"}, "Secret123"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.StageUserActivate("eve"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RPC("user_mod", []string{"eve"}, ipa.Options{"setattr": "krbPasswordExpiration=20371231235959Z"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Client().RemoteLogin("eve", "Secret123"); err != nil {
		t.Errorf("login after lifting expiry = %v", err)
	}
}
