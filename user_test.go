// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1XZq0yq8xv0w3Y6Zl5gH8eZQ7bOQb0m7mKsKq2m6eT"
)

func TestUserAddValidation(t *testing.T) {
	_, c := newFake(t)
	if _, err := c.UserAdd(&ipa.User{}, false); err == nil {
		t.Error("UserAdd: nil error")
	}
	if _, err := c.UserAddWithPassword(&ipa.User{}, "pw"); err == nil {
		t.Error("UserAddWithPassword empty username: nil error")
	}
	if _, err := c.UserAddWithPassword(&ipa.User{Username: "x"}, ""); err == nil {
		t.Error("UserAddWithPassword empty password: nil error")
	}
	if _, err := c.UserMod(&ipa.User{}); err == nil {
		t.Error("UserMod: nil error")
	}
}

func TestUserAddOmitsEmptyAttributes(t *testing.T) {
	c, f := newFakeIPA(t, 200, envelope(`{"result":{"uid":["eve"]},"value":"eve","summary":""}`))
	if _, err := c.UserAdd(&ipa.User{Username: "eve", First: "Eve", Last: "E"}, false); err != nil {
		t.Fatal(err)
	}
	opts := f.Calls()[0].Options
	delete(opts, "version")
	if want := map[string]any{"givenname": "Eve", "sn": "E"}; !reflect.DeepEqual(opts, want) {
		t.Errorf("options %v, want %v", opts, want)
	}
}

func TestUserAddWithPasswordLogsIn(t *testing.T) {
	s, c := newFake(t)
	u := &ipa.User{Username: "carol", First: "Carol", Last: "C", Email: "carol@example.com"}
	if _, err := c.UserAddWithPassword(u, "Secret-pw-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Client().RemoteLogin("carol", "Secret-pw-1"); err != nil {
		t.Errorf("login: %v", err)
	}
}

func TestUserModFields(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("dave", ipatest.User{})
	k, err := ipa.NewSSHAuthorizedKey(keyA)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.UserMod(&ipa.User{Username: "dave", First: "D", Last: "V", HomeDir: "/h/dave", Shell: "/bin/zsh", Email: "d@x.org", SSHAuthKeys: []*ipa.SSHAuthorizedKey{k}})
	if err != nil {
		t.Fatal(err)
	}
	if got.HomeDir != "/h/dave" || got.Shell != "/bin/zsh" || got.Email != "d@x.org" || len(got.SSHAuthKeys) != 1 || got.SSHAuthKeys[0].Fingerprint != k.Fingerprint {
		t.Errorf("got %+v", got)
	}
	if u, _ := s.User("dave"); u.HomeDir != "/h/dave" || u.Shell != "/bin/zsh" || u.Email != "d@x.org" || len(u.SSHPubKeys) != 1 {
		t.Errorf("server user %+v", u)
	}
}

func TestResetPasswordUnit(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("erin", ipatest.User{})
	pw, err := c.ResetPassword("erin")
	if err != nil || pw == "" {
		t.Fatalf("pw = %q, err = %v", pw, err)
	}
	if u, _ := s.User("erin"); u.PasswdExpire.IsZero() || u.PasswdExpire.After(time.Now()) {
		t.Error("user not expired")
	}
}

func TestResetPasswordEmpty(t *testing.T) {
	s, c := newFake(t)
	s.Handle("user_mod", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{"uid": []string{"erin"}}}, nil
	})
	if _, err := c.ResetPassword("erin"); err == nil {
		t.Error("nil error")
	}
}

func TestChangePasswordOTPOption(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("frank", ipatest.User{Password: "old-password-1"})
	if err := c.ChangePassword("frank", "old-password-1", "new-password-1", "123456"); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, call := range s.Calls() {
		if call.Method == "passwd" {
			found = true
			if call.Options["otp"] != "123456" {
				t.Errorf("options = %v", call.Options)
			}
		}
	}
	if !found {
		t.Error("no passwd call")
	}
}

func TestSetPasswordUnknownStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-IPA-Pwchange-Result", "error")
	}))
	t.Cleanup(ts.Close)
	c := ipa.NewClientCustomHttp(strings.TrimPrefix(ts.URL, "https://"), "R", ts.Client())
	if err := c.SetPassword("u", "a", "b", ""); err == nil || !strings.Contains(err.Error(), "Unknown status") {
		t.Errorf("err = %v", err)
	}
}

func TestSetAuthTypesUnit(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("gina", ipatest.User{})
	if err := c.SetAuthTypes("gina", []string{"otp"}); err != nil {
		t.Fatal(err)
	}
	u, err := c.UserShow("gina")
	if err != nil || !u.OTPOnly() {
		t.Fatalf("OTPOnly: %+v, %v", u, err)
	}
	if err := c.SetAuthTypes("gina", nil); err != nil {
		t.Fatal(err)
	}
	calls := s.Calls()
	if v, ok := calls[len(calls)-1].Options["ipauserauthtype"]; !ok || v != "" {
		t.Errorf("option = %v (present %v)", v, ok)
	}
	if su, _ := s.User("gina"); len(su.AuthTypes) != 0 {
		t.Errorf("AuthTypes = %v", su.AuthTypes)
	}
}

func TestUserDeleteUnit(t *testing.T) {
	s, c := newFake(t)
	for _, n := range []string{"u1", "u2", "u3", "u4"} {
		s.AddUser(n, ipatest.User{})
	}
	if err := c.UserDelete(false, true, "u1", "u2"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"u1", "u2"} {
		if _, ok := s.User(n); ok {
			t.Errorf("%s still exists", n)
		}
	}
	if err := c.UserDelete(true, true, "u3"); err != nil {
		t.Fatal(err)
	}
	if u, ok := s.User("u3"); !ok || !u.Preserved {
		t.Errorf("u3 = %+v, %v", u, ok)
	}
	if err := c.UserDelete(false, false, "missing", "u4"); err != nil {
		t.Errorf("continue mode: %v", err)
	}
	if _, ok := s.User("u4"); ok {
		t.Error("u4 still exists")
	}
}

func TestUserHelpers(t *testing.T) {
	u := &ipa.User{Groups: []string{"admins"}, AuthTypes: []string{"otp"}}
	if !u.HasGroup("admins") || u.HasGroup("x") || !u.OTPOnly() {
		t.Error("HasGroup/OTPOnly")
	}
	if (&ipa.User{AuthTypes: []string{"otp", "password"}}).OTPOnly() {
		t.Error("OTPOnly with two types")
	}

	a, err := ipa.NewSSHAuthorizedKey(keyA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ipa.NewSSHAuthorizedKey(`from="10.0.0.1",no-pty ` + keyB + " bob@host")
	if err != nil {
		t.Fatal(err)
	}
	u.AddSSHAuthorizedKey(a)
	u.AddSSHAuthorizedKey(b)
	a2, _ := ipa.NewSSHAuthorizedKey(keyA + " renamed")
	u.AddSSHAuthorizedKey(a2) // same fingerprint: replaced
	if len(u.SSHAuthKeys) != 2 || u.SSHAuthKeys[0].Comment != "renamed" {
		t.Fatalf("keys = %+v", u.SSHAuthKeys)
	}
	want := []string{keyA + " renamed", `from="10.0.0.1",no-pty ` + keyB + " bob@host"}
	if got := u.FormatSSHAuthorizedKeys(); !reflect.DeepEqual(got, want) {
		t.Errorf("Format = %q, want %q", got, want)
	}
	if got := b.String(); got != want[1] {
		t.Errorf("String = %q", got)
	}
	if j, err := b.MarshalJSON(); err != nil || string(j) != `"from=\"10.0.0.1\",no-pty `+keyB+` bob@host"` {
		t.Errorf("MarshalJSON = %s, %v", j, err)
	}
	u.RemoveSSHAuthorizedKey("nope")
	u.RemoveSSHAuthorizedKey(a.Fingerprint)
	if len(u.SSHAuthKeys) != 1 || u.SSHAuthKeys[0].Fingerprint != b.Fingerprint {
		t.Errorf("after remove: %+v", u.SSHAuthKeys)
	}
	if _, err := ipa.NewSSHAuthorizedKey("junk"); err == nil {
		t.Error("junk key accepted")
	}
}
