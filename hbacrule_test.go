// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestHBACRule_EmptyKeys(t *testing.T) {
	s, c := newFake(t)
	n := len(s.Calls())
	for name, err := range map[string]error{
		"show":    func() error { _, err := c.HBACRuleShow(""); return err }(),
		"add":     func() error { _, err := c.HBACRuleAdd(&ipa.HBACRule{}); return err }(),
		"add nil": func() error { _, err := c.HBACRuleAdd(nil); return err }(),
		"delete":  c.HBACRuleDelete(),
		"enable":  c.HBACRuleEnable(""),
		"disable": c.HBACRuleDisable(""),
		"member":  func() error { _, err := c.HBACRuleAddUser("", []string{"admin"}, nil); return err }(),
		"nothing": func() error { _, err := c.HBACRuleAddHost("allow_all", nil, []string{}); return err }(),
	} {
		if err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if len(s.Calls()) != n {
		t.Errorf("sent %d requests", len(s.Calls())-n)
	}
}

func TestHBACRuleAdd_SendsOnlySetFields(t *testing.T) {
	s, c := newFake(t)
	if _, err := c.HBACRuleAdd(&ipa.HBACRule{Name: "r", HostCategory: "all", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	o := lastFind(s).Options
	delete(o, "version")
	if !reflect.DeepEqual(o, map[string]any{"hostcategory": "all", "all": true}) {
		t.Errorf("options = %v", o)
	}
}

func TestHBACRuleDelete_OneCall(t *testing.T) {
	s, c := newFake(t)
	s.AddHBACRule("a", ipatest.HBACRule{})
	s.AddHBACRule("b", ipatest.HBACRule{})
	if err := c.HBACRuleDelete("a", "b"); err != nil {
		t.Fatal(err)
	}
	if got := lastFind(s).Args; !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("args = %v", got)
	}
	if rules, _ := c.HBACRuleFind(nil); len(rules) != 1 {
		t.Errorf("left %+v", rules)
	}
}

func TestHBACRuleShow_FakeRule(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("h.test.local", ipatest.Host{HostGroups: []string{"web"}})
	s.AddHBACRule("r", ipatest.HBACRule{Disabled: true, HostGroups: []string{"web"}, ServiceGroups: []string{"ftp"}})
	got, err := c.HBACRuleShow("r")
	want := &ipa.HBACRule{Name: "r", HostGroups: []string{"web"}, ServiceGroups: []string{"ftp"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err = c.HBACRuleRemoveHost("r", nil, []string{"web"}); err != nil || got.HostGroups != nil {
		t.Errorf("remove hostgroup = %+v, %v", got, err)
	}
}
