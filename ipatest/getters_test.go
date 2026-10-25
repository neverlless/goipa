// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"slices"
	"testing"
	"time"

	"github.com/neverlless/goipa/ipatest"
)

func TestGetters_Copies(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	c := s.ClientAs("admin")

	s.AddHBACRule("r1", ipatest.HBACRule{Description: "d", Users: []string{"bob"}})
	h, ok := s.HBACRule("r1")
	if !ok || h.Description != "d" || !slices.Equal(h.Users, []string{"bob"}) {
		t.Fatalf("HBACRule = %+v, %v", h, ok)
	}
	h.Users[0] = "mallory"
	if h, _ := s.HBACRule("r1"); h.Users[0] != "bob" {
		t.Error("HBACRule returned the stored slice")
	}
	if err := c.HBACRuleDisable("r1"); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.HBACRule("r1"); !h.Disabled {
		t.Error("HBACRule does not see hbacrule_disable")
	}
	if _, ok := s.HBACRule("nope"); ok {
		t.Error("HBACRule(nope) found")
	}

	s.AddSudoRule("s1", ipatest.SudoRule{Options: []string{"!authenticate"}})
	sr, ok := s.SudoRule("s1")
	if !ok || !slices.Equal(sr.Options, []string{"!authenticate"}) {
		t.Fatalf("SudoRule = %+v, %v", sr, ok)
	}
	sr.Options[0] = "x"
	if sr, _ := s.SudoRule("s1"); sr.Options[0] != "!authenticate" {
		t.Error("SudoRule returned the stored slice")
	}
	if _, ok := s.SudoRule("nope"); ok {
		t.Error("SudoRule(nope) found")
	}

	if p, ok := s.PwPolicy("global_policy"); !ok || p.MinLength != 8 || p.MaxLife != 90*24*time.Hour {
		t.Errorf("global PwPolicy = %+v, %v", p, ok)
	}
	if _, ok := s.PwPolicy("nope"); ok {
		t.Error("PwPolicy(nope) found")
	}

	r, ok := s.Role("User Administrator")
	if !ok || r.Name != "User Administrator" || len(r.Privileges) == 0 {
		t.Fatalf("Role = %+v, %v", r, ok)
	}
	r.Privileges[0] = "x"
	if r, _ := s.Role("User Administrator"); r.Privileges[0] == "x" {
		t.Error("Role returned the stored slice")
	}
	p, ok := s.Privilege("User Administrators")
	if !ok || p.Name != "User Administrators" || len(p.Permissions) == 0 {
		t.Fatalf("Privilege = %+v, %v", p, ok)
	}
	p.Permissions[0] = "x"
	if p, _ := s.Privilege("User Administrators"); p.Permissions[0] == "x" {
		t.Error("Privilege returned the stored slice")
	}
	pm, ok := s.Permission("System: Add Users")
	if !ok || pm.Name != "System: Add Users" || len(pm.Rights) == 0 {
		t.Fatalf("Permission = %+v, %v", pm, ok)
	}
	pm.Rights[0] = "x"
	if pm, _ := s.Permission("System: Add Users"); pm.Rights[0] == "x" {
		t.Error("Permission returned the stored slice")
	}
	for name, ok := range map[string]bool{
		"role": func() bool { _, ok := s.Role("nope"); return ok }(),
		"priv": func() bool { _, ok := s.Privilege("nope"); return ok }(),
		"perm": func() bool { _, ok := s.Permission("nope"); return ok }(),
	} {
		if ok {
			t.Errorf("%s nope found", name)
		}
	}
	if _, err := c.RoleShow("User Administrator"); err != nil {
		t.Fatal(err)
	}
}
