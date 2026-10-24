// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestAutomember_NoRPCOnBadInput(t *testing.T) {
	s, c := newFake(t)
	g := ipa.AutomemberGroup
	cases := map[string]func() error{
		"bad type show":    func() error { _, err := c.AutomemberShow("user", "x"); return err },
		"bad type find":    func() error { _, err := c.AutomemberFind("", nil); return err },
		"bad type rebuild": func() error { return c.AutomemberRebuild("hosts") },
		"bad type default": func() error { _, err := c.AutomemberDefaultGroup("Group"); return err },
		"empty name":       func() error { _, err := c.AutomemberShow(g, ""); return err },
		"empty add name":   func() error { _, err := c.AutomemberAdd(g, "", "d"); return err },
		"delete nothing":   func() error { return c.AutomemberDelete(g) },
		"delete gap":       func() error { return c.AutomemberDelete(g, "x", "") },
		"empty key":        func() error { _, err := c.AutomemberAddCondition(g, "x", "", []string{"^a"}, nil); return err },
		"no conditions":    func() error { _, err := c.AutomemberAddCondition(g, "x", "uid", nil, []string{}); return err },
		"remove nothing":   func() error { _, err := c.AutomemberRemoveCondition(g, "x", "uid", nil, nil); return err },
		"empty default":    func() error { return c.AutomemberSetDefaultGroup(g, "") },
		"bad type remove":  func() error { return c.AutomemberRemoveDefaultGroup("x") },
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls sent", n)
	}
}

func TestAutomember_DefaultGroupNotPreferredOverRule(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("ruled", ipatest.Group{})
	s.AddGroup("fallback", ipatest.Group{})
	if _, err := c.AutomemberAdd(ipa.AutomemberGroup, "ruled", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AutomemberAddCondition(ipa.AutomemberGroup, "ruled", "givenname", []string{"^Al"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "fallback"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*ipa.User{{Username: "alice", First: "Alice", Last: "A"}, {Username: "bob", First: "Bob", Last: "B"}} {
		if _, err := c.UserAdd(u, false); err != nil {
			t.Fatal(err)
		}
	}
	ruled, _ := s.Group("ruled")
	fallback, _ := s.Group("fallback")
	if !slices.Equal(ruled.Members, []string{"alice"}) || !slices.Equal(fallback.Members, []string{"bob"}) {
		t.Errorf("ruled %v, fallback %v", ruled.Members, fallback.Members)
	}
}

func TestAutomember_StageUserActivate(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("fallback", ipatest.Group{})
	if err := c.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "fallback"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.StageUserAdd(&ipa.User{Username: "carol", First: "Carol", Last: "C"}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Group("fallback"); len(g.Members) != 0 {
		t.Fatalf("staged user already in %v", g.Members)
	}
	if _, err := c.StageUserActivate("carol"); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Group("fallback"); !slices.Equal(g.Members, []string{"carol"}) {
		t.Errorf("fallback members = %v", g.Members)
	}
}
