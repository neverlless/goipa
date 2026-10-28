// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// strictGroup puts bob into a group whose policy is p, stricter than global.
func strictGroup(t *testing.T, p ipatest.PwPolicy) *ipatest.Server {
	t.Helper()
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{Password: "Oldpass-12x", Groups: []string{"strict"}})
	s.AddGroup("strict", ipatest.Group{Members: []string{"bob"}})
	p.Priority = 10
	s.SetPwPolicy("strict", p)
	return s
}

func policyHeader(t *testing.T, s *ipatest.Server, old, nw string) (string, string) {
	t.Helper()
	res := postForm(t, s, "/ipa/session/change_password", url.Values{"user": {"bob"}, "old_password": {old}, "new_password": {nw}}, true)
	return res.Header.Get("X-IPA-Pwchange-Result"), res.Header.Get("X-IPA-Pwchange-Policy-Error")
}

func TestChangePassword_GroupPolicyStricter(t *testing.T) {
	s := strictGroup(t, ipatest.PwPolicy{MinLength: 12})
	s.AddUser("carol", ipatest.User{Password: "Oldpass-12x"})
	if r, m := policyHeader(t, s, "Oldpass-12x", "tenchars-1"); r != "policy-error" || m != "Constraint violation: Password is too short" {
		t.Errorf("form: %q %q", r, m)
	}
	err := s.ClientAs("bob").ChangePassword("bob", "Oldpass-12x", "tenchars-1", "")
	if ipaCode(t, err) != ipa.CodeDatabase || !strings.Contains(err.Error(), "Password is too short") {
		t.Errorf("passwd: %v", err)
	}
	if err := s.Client().SetPassword("carol", "Oldpass-12x", "tenchars-1", ""); err != nil {
		t.Errorf("outside the group: %v", err)
	}
	if err := s.Client().SetPassword("bob", "Oldpass-12x", "twelvechars-1", ""); err != nil {
		t.Errorf("long enough: %v", err)
	}
}

func TestChangePassword_CharacterClasses(t *testing.T) {
	s := strictGroup(t, ipatest.PwPolicy{MinClasses: 3})
	if r, m := policyHeader(t, s, "Oldpass-12x", "abcdefghijkl"); r != "policy-error" || m != "Constraint violation: Password is too simple" {
		t.Errorf("one class: %q %q", r, m)
	}
	if err := s.Client().SetPassword("bob", "Oldpass-12x", "abcDefgh1jkl", ""); err != nil {
		t.Errorf("three classes: %v", err)
	}
}

func TestChangePassword_History(t *testing.T) {
	s := strictGroup(t, ipatest.PwPolicy{HistoryLength: 2})
	c := s.Client()
	const p0, p1, p2 = "Oldpass-12x", "Newpass-34y", "Third-pass-56z"
	if err := c.SetPassword("bob", p0, p1, ""); err != nil {
		t.Fatal(err)
	}
	if r, m := policyHeader(t, s, p1, p1); r != "policy-error" || m != "Constraint violation: Password reuse not permitted" {
		t.Errorf("reuse current: %q %q", r, m)
	}
	if err := c.SetPassword("bob", p1, p2, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("bob", p2, p1, ""); !errors.Is(err, ipa.ErrPasswordPolicy) {
		t.Errorf("one back: %v", err)
	}
	// p0 was set before the policy kept a history, so it is not in it.
	if err := c.SetPassword("bob", p2, p0, ""); err != nil {
		t.Errorf("two back: %v", err)
	}
	err := s.ClientAs("admin").ChangePassword("bob", p0, p0, "")
	if ipaCode(t, err) != ipa.CodeDatabase || !strings.Contains(err.Error(), "Password reuse not permitted") {
		t.Errorf("admin reuse: %v", err)
	}
}

func TestChangePassword_AdminSkipsLengthAndClasses(t *testing.T) {
	s := strictGroup(t, ipatest.PwPolicy{MinLength: 12, MinClasses: 3, MinLife: time.Hour})
	if err := s.ClientAs("admin").ChangePassword("bob", "Oldpass-12x", "short", ""); err != nil {
		t.Errorf("admin: %v", err)
	}
}

func TestChangePassword_MinLife(t *testing.T) {
	s := strictGroup(t, ipatest.PwPolicy{MinLife: time.Hour})
	c := s.Client()
	// admin-set passwords are expired, so the first change is allowed at once
	if err := s.ClientAs("admin").ChangePassword("bob", "Oldpass-12x", "Adminpass-12x", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("bob", "Adminpass-12x", "Newpass-34y", ""); err != nil {
		t.Fatal(err)
	}
	if r, m := policyHeader(t, s, "Newpass-34y", "Third-pass-56z"); r != "policy-error" || m != "Constraint violation: Too soon to change password" {
		t.Errorf("form: %q %q", r, m)
	}
	err := s.ClientAs("bob").ChangePassword("bob", "Newpass-34y", "Third-pass-56z", "")
	if ipaCode(t, err) != ipa.CodeDatabase || !strings.Contains(err.Error(), "Too soon") {
		t.Errorf("passwd: %v", err)
	}
	if err := s.ClientAs("admin").ChangePassword("bob", "Newpass-34y", "Third-pass-56z", ""); err != nil {
		t.Errorf("admin: %v", err)
	}
}
