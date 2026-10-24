// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestHBACRuleFind_AllFields(t *testing.T) {
	s, c := newFake(t)
	s.AddHBACRule("r1", ipatest.HBACRule{
		Description: "d", UserCategory: "all", HostCategory: "all", ServiceCategory: "all",
		Users: []string{"u"}, Groups: []string{"g"}, Hosts: []string{"h"}, HostGroups: []string{"hg"},
		Services: []string{"sshd"}, ServiceGroups: []string{"sg"},
	})
	s.AddHBACRule("r2", ipatest.HBACRule{Disabled: true})
	got, err := c.HBACRuleFind(ipa.Options{"cn": "r1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []*ipa.HBACRule{{
		Name: "r1", Description: "d", Enabled: true, UserCategory: "all", HostCategory: "all", ServiceCategory: "all",
		Users: []string{"u"}, Groups: []string{"g"}, Hosts: []string{"h"}, HostGroups: []string{"hg"},
		Services: []string{"sshd"}, ServiceGroups: []string{"sg"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got[0], want[0])
	}
	got, err = c.HBACRuleFind(ipa.Options{"cn": "r2"})
	if err != nil || len(got) != 1 || got[0].Enabled {
		t.Errorf("disabled: %+v, %v", got, err)
	}
	got, err = c.HBACRuleFind(ipa.Options{"ipaenabledflag": true})
	if err != nil || len(got) != 2 { // allow_all and r1
		t.Errorf("enabled: %d rules, %v", len(got), err)
	}
	got, err = c.HBACRuleFind(ipa.Options{"cn": "allow_all"})
	if err != nil || len(got) != 1 || got[0].UserCategory != "all" || got[0].HostCategory != "all" || got[0].ServiceCategory != "all" || !got[0].Enabled {
		t.Errorf("allow_all: %+v, %v", got, err)
	}
}

func TestSudoRuleFind_AllFields(t *testing.T) {
	s, c := newFake(t)
	s.AddSudoRule("s1", ipatest.SudoRule{
		Description: "d", UserCategory: "all", HostCategory: "all", CmdCategory: "all",
		RunAsUserCategory: "all", RunAsGroupCategory: "all",
		Users: []string{"u"}, Groups: []string{"g"}, Hosts: []string{"h"}, HostGroups: []string{"hg"},
		AllowCommands: []string{"/bin/ls"}, AllowCommandGroups: []string{"acg"},
		DenyCommands: []string{"/bin/rm"}, DenyCommandGroups: []string{"dcg"},
		RunAsUsers: []string{"root"}, RunAsGroups: []string{"wheel"},
		Options: []string{"!authenticate"}, Order: 5,
	})
	s.AddSudoRule("s2", ipatest.SudoRule{Disabled: true})
	got, err := c.SudoRuleFind(ipa.Options{"cn": "s1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []*ipa.SudoRule{{
		Name: "s1", Description: "d", Enabled: true, UserCategory: "all", HostCategory: "all", CmdCategory: "all",
		RunAsUserCategory: "all", RunAsGroupCategory: "all",
		Users: []string{"u"}, Groups: []string{"g"}, Hosts: []string{"h"}, HostGroups: []string{"hg"},
		AllowCommands: []string{"/bin/ls"}, AllowCommandGroups: []string{"acg"},
		DenyCommands: []string{"/bin/rm"}, DenyCommandGroups: []string{"dcg"},
		RunAsUsers: []string{"root"}, RunAsGroups: []string{"wheel"},
		Options: []string{"!authenticate"}, Order: 5,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got[0], want[0])
	}
	got, err = c.SudoRuleFind(ipa.Options{"cn": "s2"})
	if err != nil || len(got) != 1 || got[0].Enabled {
		t.Errorf("disabled: %+v, %v", got, err)
	}
	if got, err = c.SudoRuleFind(nil); err != nil || len(got) != 2 {
		t.Errorf("all: %d rules, %v", len(got), err)
	}
}

func TestRuleFind_SendsAllAndMembers(t *testing.T) {
	s, c := newFake(t)
	opts := ipa.Options{"cn": "x"}
	for method, find := range map[string]func() error{
		"hbacrule_find": func() error { _, err := c.HBACRuleFind(opts); return err },
		"sudorule_find": func() error { _, err := c.SudoRuleFind(opts); return err },
	} {
		if err := find(); err != nil {
			t.Fatal(err)
		}
		calls := s.Calls()
		last := calls[len(calls)-1]
		if last.Method != method || last.Options["all"] != true || last.Options["no_members"] != false || !reflect.DeepEqual(last.Args, []string{""}) {
			t.Errorf("%s: call = %+v", method, last)
		}
	}
	if len(opts) != 1 {
		t.Errorf("caller options changed: %v", opts)
	}
}

func TestRuleCommands(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("alice", ipatest.User{})
	rpc := func(m string, args []string, o ipa.Options) {
		t.Helper()
		if _, err := c.RPC(m, args, o); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	rpc("hbacrule_add", []string{"h"}, nil)
	rpc("hbacrule_add_user", []string{"h"}, ipa.Options{"user": []string{"alice"}})
	rpc("sudorule_add", []string{"s"}, ipa.Options{"sudoorder": 5})
	rpc("sudorule_add_user", []string{"s"}, ipa.Options{"user": []string{"alice"}})
	rpc("sudorule_add_option", []string{"s"}, ipa.Options{"ipasudoopt": "!authenticate"})
	hr, err := c.HBACRuleFind(ipa.Options{"cn": "h"})
	if err != nil || len(hr) != 1 || !reflect.DeepEqual(hr[0].Users, []string{"alice"}) || !hr[0].Enabled {
		t.Fatalf("hbac: %+v, %v", hr, err)
	}
	sr, err := c.SudoRuleFind(ipa.Options{"cn": "s"})
	if err != nil || len(sr) != 1 || sr[0].Order != 5 || !reflect.DeepEqual(sr[0].Options, []string{"!authenticate"}) || !reflect.DeepEqual(sr[0].Users, []string{"alice"}) {
		t.Fatalf("sudo: %+v, %v", sr, err)
	}
	rpc("hbacrule_del", []string{"h"}, nil)
	rpc("sudorule_del", []string{"s"}, nil)
	if _, err := c.RPC("hbacrule_del", []string{"h"}, nil); !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if hr, _ = c.HBACRuleFind(ipa.Options{"cn": "h"}); len(hr) != 0 {
		t.Errorf("not deleted: %+v", hr)
	}
}
