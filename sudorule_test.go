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

func TestSudoRule_NoRequest(t *testing.T) {
	s, c := newFake(t)
	for name, call := range map[string]func() error{
		"delete none": func() error { return c.SudoRuleDelete() },
		"show empty":  func() error { _, err := c.SudoRuleShow(""); return err },
		"add nil":     func() error { _, err := c.SudoRuleAdd(nil); return err },
		"add empty":   func() error { _, err := c.SudoRuleAdd(&ipa.SudoRule{}); return err },
		"enable":      func() error { return c.SudoRuleEnable("") },
		"disable":     func() error { return c.SudoRuleDisable("") },
		"user empty":  func() error { _, err := c.SudoRuleAddUser("", []string{"u"}, nil); return err },
		"user none":   func() error { _, err := c.SudoRuleAddUser("r", nil, nil); return err },
		"option none": func() error { _, err := c.SudoRuleAddOption("r"); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls reached the server", n)
	}
}

func TestSudoRuleAdd_Options(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.SudoRuleAdd(&ipa.SudoRule{Name: "r", UserCategory: "all", HostCategory: "x"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"all": true, "usercategory": "all"}
	o := lastFind(s).Options
	delete(o, "version")
	if !reflect.DeepEqual(o, want) {
		t.Errorf("options = %v", o)
	}
}

func TestSudoRuleShow_Members(t *testing.T) {
	s, c := newFake(t)
	s.AddSudoRule("r", ipatest.SudoRule{Users: []string{"u"}, RunAsUserGroups: []string{"g"}, Order: 3, Disabled: true})
	r, err := c.SudoRuleShow("r")
	if err != nil {
		t.Fatal(err)
	}
	want := &ipa.SudoRule{Name: "r", Users: []string{"u"}, RunAsUserGroups: []string{"g"}, Order: 3}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("rule = %+v", r)
	}
}

func TestSudoRuleAddHost_HostGroupMissing(t *testing.T) {
	s, c := newFake(t)
	s.AddSudoRule("r", ipatest.SudoRule{})
	r, err := c.SudoRuleAddHost("r", []string{"ext.example.test"}, []string{"hg"})
	var me *ipa.MemberError
	if !errors.As(err, &me) || len(me.Failures) != 1 || me.Failures[0].Type != "hostgroup" {
		t.Fatalf("err = %v", err)
	}
	if r == nil || r.Hosts != nil {
		t.Errorf("rule = %+v", r)
	}
}
