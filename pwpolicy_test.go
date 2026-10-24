// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestPwPolicy_BoolForms(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{{`true`, true}, {`[true]`, true}, {`"TRUE"`, true}, {`["FALSE"]`, false}} {
		s := ipatest.NewServer(t)
		s.Handle("pwpolicy_show", func(ipatest.Call) (any, *ipa.IpaError) {
			return map[string]any{"result": map[string]any{"cn": []string{"global_policy"}, "ipapwddictcheck": rawJSON(tc.raw)}}, nil
		})
		p, err := s.ClientAs("admin").PwPolicyShow("")
		if err != nil || p.DictCheck != tc.want {
			t.Errorf("%s: DictCheck = %v, %v; want %v", tc.raw, p, err, tc.want)
		}
	}
}

type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func TestPwPolicy_Credits(t *testing.T) {
	s := ipatest.NewServer(t)
	s.SetPwPolicy("global_policy", ipatest.PwPolicy{
		MaxLife: 30 * 24 * time.Hour, MinLife: 2 * time.Hour, MinLength: 10, MaxFailures: 3,
		FailureInterval: 90 * time.Second, LockoutDuration: 5 * time.Minute, GraceLimit: -1,
		DictCheck: true, UserCheck: true, HistoryLength: 5, MinClasses: 3, MaxRepeat: 2, MaxSequence: 4,
		DigitCredit: 1, UpperCredit: -1, LowerCredit: 2, OtherCredit: -2,
	})
	got, err := s.ClientAs("admin").PwPolicyShow("")
	if err != nil {
		t.Fatal(err)
	}
	want := ipa.PwPolicy{
		Name: "global_policy", MaxLife: 30 * 24 * time.Hour, MinLife: 2 * time.Hour, MinLength: 10, MaxFailures: 3,
		FailureInterval: 90 * time.Second, LockoutDuration: 5 * time.Minute, GraceLimit: -1,
		DictCheck: true, UserCheck: true, HistoryLength: 5, MinClasses: 3, MaxRepeat: 2, MaxSequence: 4,
		DigitCredit: 1, UpperCredit: -1, LowerCredit: 2, OtherCredit: -2,
	}
	if *got != want {
		t.Errorf("got  %+v\nwant %+v", *got, want)
	}
}

func TestPwPolicy_OldServerNoCredits(t *testing.T) {
	s := ipatest.NewServer(t)
	s.Handle("pwpolicy_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{"cn": []string{"global_policy"}, "krbpwdminlength": []string{"8"}}}, nil
	})
	p, err := s.ClientAs("admin").PwPolicyShow("")
	if err != nil || p.MinLength != 8 || p.GraceLimit != 0 || p.DigitCredit != 0 || p.OtherCredit != 0 {
		t.Errorf("policy = %+v, %v", p, err)
	}
}

func TestUserPwPolicy_EmptyName(t *testing.T) {
	s := ipatest.NewServer(t)
	if _, err := s.ClientAs("admin").UserPwPolicy(""); err == nil {
		t.Error("no error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestPwPolicyShow_Wire(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("ops", ipatest.Group{})
	s.SetPwPolicy("ops", ipatest.PwPolicy{Priority: 5, MinLength: 12})
	c := s.ClientAs("admin")
	if _, err := c.PwPolicyShow(""); err != nil {
		t.Fatal(err)
	}
	p, err := c.PwPolicyShow("ops")
	if err != nil || p.Name != "ops" || p.Priority != 5 || p.MinLength != 12 {
		t.Fatalf("ops = %+v, %v", p, err)
	}
	calls := s.Calls()
	if len(calls[0].Args) != 0 || fmt.Sprint(calls[1].Args) != "[ops]" {
		t.Errorf("args = %v, %v", calls[0].Args, calls[1].Args)
	}
	if _, err := c.PwPolicyShow("nope"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("unknown group err = %v", err)
	}
	s.AddUser("bob", ipatest.User{First: "B", Last: "B"})
	if _, err := c.UserPwPolicy("bob"); err != nil {
		t.Fatal(err)
	}
	for _, call := range s.Calls() {
		if _, ok := call.Options["no_members"]; ok || call.Options["all"] != true {
			t.Errorf("options = %v; want all without no_members", call.Options)
		}
	}
}

func TestPwPolicyShow_UnknownOption(t *testing.T) {
	s := ipatest.NewServer(t)
	_, err := s.ClientAs("admin").RPC("pwpolicy_show", nil, ipa.Options{"all": true, "no_members": false})
	var ierr *ipa.IpaError
	if !errors.As(err, &ierr) || ierr.Code != ipa.CodeOption || ierr.Name != "OptionError" ||
		ierr.Message != "Unknown option: no_members" {
		t.Errorf("err = %#v", err)
	}
}

func TestUserPwPolicy_Resolution(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "B", Last: "B", Groups: []string{"inner"}})
	s.AddUser("eve", ipatest.User{First: "E", Last: "E"})
	s.AddGroup("inner", ipatest.Group{})
	s.AddGroup("outer", ipatest.Group{MemberGroups: []string{"inner"}})
	s.SetPwPolicy("inner", ipatest.PwPolicy{Priority: 20, MinLength: 12})
	s.SetPwPolicy("outer", ipatest.PwPolicy{Priority: 10, MinLength: 15})
	c := s.ClientAs("admin")
	if p, err := c.UserPwPolicy("bob"); err != nil || p.Name != "outer" || p.MinLength != 15 {
		t.Errorf("bob = %+v, %v", p, err)
	}
	if p, err := c.UserPwPolicy("eve"); err != nil || p.Name != "global_policy" {
		t.Errorf("eve = %+v, %v", p, err)
	}
	if _, err := c.UserPwPolicy("ghost"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("ghost err = %v", err)
	}
}

func TestPwPolicy_AddDelAndLoginUseGlobal(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "B", Last: "B", Password: "Secret123!"})
	c := s.ClientAs("admin")
	if _, err := c.RPC("pwpolicy_add", []string{"nogroup"}, ipa.Options{"cospriority": 1}); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("add for unknown group err = %v", err)
	}
	s.AddGroup("g", ipatest.Group{})
	if _, err := c.RPC("pwpolicy_add", []string{"g"}, ipa.Options{}); err == nil {
		t.Error("add without cospriority succeeded")
	}
	s.SetPwPolicy("global_policy", ipatest.PwPolicy{MaxFailures: 2, MinLength: 3})
	for range 2 {
		_ = s.Client().RemoteLogin("bob", "bad")
	}
	if err := s.Client().RemoteLogin("bob", "Secret123!"); err == nil {
		t.Error("login succeeded after MaxFailures wrong passwords")
	}
}

func TestPwPolicy_ZeroMaxFailuresNoLockout(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "B", Last: "B", Password: "Secret123!"})
	s.SetPwPolicy("global_policy", ipatest.PwPolicy{MinLength: 3})
	for range 20 {
		_ = s.Client().RemoteLogin("bob", "bad")
	}
	if err := s.Client().RemoteLogin("bob", "Secret123!"); err != nil {
		t.Errorf("login with MaxFailures 0: %v", err)
	}
}

func TestPwPolicy_DelAndMinLength(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{First: "B", Last: "B", Password: "Secret123!"})
	s.AddGroup("g", ipatest.Group{})
	c := s.ClientAs("admin")
	if _, err := c.RPC("pwpolicy_add", []string{"g"}, ipa.Options{"cospriority": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RPC("pwpolicy_del", []string{"g"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PwPolicyShow("g"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("show after del err = %v", err)
	}
	s.SetPwPolicy("global_policy", ipatest.PwPolicy{MinLength: 12, MaxFailures: 6})
	if err := s.Client().SetPassword("bob", "Secret123!", "short1!", ""); err == nil {
		t.Error("password below MinLength accepted")
	}
	if err := s.Client().SetPassword("bob", "Secret123!", "longenough123!", ""); err != nil {
		t.Errorf("long password rejected: %v", err)
	}
}
