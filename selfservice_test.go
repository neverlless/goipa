// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestSelfServiceFind_Defaults(t *testing.T) {
	for ver, n := range map[string]int{"4.9.13": 5, "4.12.2": 6, "4.13.4": 6} {
		s, c := newFake(t)
		s.SetVersion(ver)
		rules, err := c.SelfServiceFind(nil)
		if err != nil || len(rules) != n {
			t.Fatalf("%s: %d rules, %v; want %d", ver, len(rules), err, n)
		}
		if rules[1].Name != "User Self service" || rules[1].Permissions[0] != "write" || !slices.Contains(rules[1].Attrs, "manager") {
			t.Errorf("%s: rule = %+v", ver, rules[1])
		}
	}
}

func TestSelfServiceFind_FilterAttrs(t *testing.T) {
	_, c := newFake(t)
	rules, err := c.SelfServiceFind(ipa.Options{"attrs": "manager"})
	if err != nil || len(rules) != 1 || rules[0].Name != "User Self service" {
		t.Errorf("rules = %+v, %v", rules, err)
	}
	rules, err = c.SelfServiceFind(ipa.Options{"aciname": "nope"})
	if err != nil || len(rules) != 0 {
		t.Errorf("aciname: %+v, %v", rules, err)
	}
}

func TestSelfServiceShow_NotFound(t *testing.T) {
	_, c := newFake(t)
	r, err := c.SelfServiceShow("Self can write own password")
	if err != nil || len(r.Attrs) != 4 {
		t.Fatalf("show = %+v, %v", r, err)
	}
	if _, err = c.SelfServiceShow("nope"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if _, err = c.SelfServiceShow(""); err == nil || err.Error() != "ipa: self-service rule name is required" {
		t.Errorf("empty: %v", err)
	}
}

func TestSelfServiceFind_PlainUserHidden(t *testing.T) {
	s, _ := newFake(t)
	s.AddUser("bob", ipatest.User{})
	bob := s.ClientAs("bob")
	rules, err := bob.SelfServiceFind(nil)
	if err != nil || len(rules) != 0 {
		t.Errorf("plain: %d rules, %v", len(rules), err)
	}
	if _, err = bob.SelfServiceShow("User Self service"); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("show: %v", err)
	}
	s.GrantPrivilege("bob", "RBAC Readers")
	if rules, err = bob.SelfServiceFind(nil); err != nil || len(rules) != 6 {
		t.Errorf("reader: %d rules, %v", len(rules), err)
	}
}
