// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestShowEntry_SendsAllAndMembers(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	e, err := ipa.ShowEntry(context.Background(), c, "user_show", []string{"u1"})
	if err != nil || e.Str("uid") != "u1" {
		t.Fatalf("e = %v, err = %v", e, err)
	}
	o := lastFind(s).Options
	if o["all"] != true || o["no_members"] != false {
		t.Errorf("options = %v", o)
	}
}

func TestShowEntry_NoMembersOnlyWhenCatalogued(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	_, _ = ipa.ShowEntry(context.Background(), c, "dnszone_show", []string{"example.test."})
	if o := lastFind(s).Options; o["all"] != true || o["no_members"] != nil {
		t.Errorf("dnszone_show options = %v", o)
	}
	if _, err := ipa.ShowEntry(context.Background(), c, "user_show", []string{"u1"}); err != nil {
		t.Fatal(err)
	}
	if o := lastFind(s).Options; o["no_members"] != false {
		t.Errorf("user_show options = %v", o)
	}
}

func TestFindTyped_Truncated(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	s.AddUser("u2", ipatest.User{})
	es, err := ipa.FindTyped(context.Background(), c, "user_find", nil, ipa.Options{"sizelimit": 1})
	if !errors.Is(err, ipa.ErrTruncated) || len(es) != 1 {
		t.Fatalf("len = %d, err = %v", len(es), err)
	}
}

func TestFindTyped_CallerOptionsWin(t *testing.T) {
	s, c := newFake(t)
	s.AddUser("u1", ipatest.User{})
	in := ipa.Options{"no_members": true}
	if _, err := ipa.FindTyped(context.Background(), c, "user_find", nil, in); err != nil {
		t.Fatal(err)
	}
	o := lastFind(s).Options
	if o["no_members"] != true || o["all"] != true {
		t.Errorf("options = %v", o)
	}
	if !reflect.DeepEqual(in, ipa.Options{"no_members": true}) {
		t.Errorf("caller map changed: %v", in)
	}
}

func TestMembers_Empty(t *testing.T) {
	s, c := newFake(t)
	_, err := ipa.Members(context.Background(), c, "group_add_member", []string{"g"}, map[string][]string{"user": nil, "group": {}})
	if err == nil {
		t.Fatal("want error")
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls logged", n)
	}
}

func TestMembers_Failures(t *testing.T) {
	s, c := newFake(t)
	s.AddGroup("g", ipatest.Group{})
	e, err := ipa.Members(context.Background(), c, "group_add_member", []string{"g"}, map[string][]string{"user": {"ghost"}})
	var me *ipa.MemberError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v", err)
	}
	if e.Str("cn") != "g" {
		t.Errorf("entry empty: %s", e.Raw())
	}
}

func TestMembers_OneHelper(t *testing.T) {
	s, c := newFake(t)
	s.AddHostGroup("hg", ipatest.HostGroup{})
	s.AddHBACRule("hr", ipatest.HBACRule{})
	s.AddSudoRule("sr", ipatest.SudoRule{})
	s.AddService("HTTP/web.example.test@EXAMPLE.TEST", ipatest.Service{})
	calls := map[string]func() (any, error){
		"hostgroup": func() (any, error) { return c.HostGroupAddMember("hg", []string{"ghost.example.test"}, nil) },
		"hbacrule":  func() (any, error) { return c.HBACRuleAddUser("hr", []string{"ghost"}, nil) },
		"sudorule":  func() (any, error) { return c.SudoRuleAddHost("sr", nil, []string{"ghost"}) },
		"service": func() (any, error) {
			return c.ServiceAllowRetrieveKeytab("HTTP/web.example.test@EXAMPLE.TEST", ipa.KeytabAccess{Users: []string{"ghost"}})
		},
	}
	for name, call := range calls {
		obj, err := call()
		if _, ok := errors.AsType[*ipa.MemberError](err); !ok {
			t.Errorf("%s: err = %v, want *MemberError", name, err)
		}
		if reflect.ValueOf(obj).IsNil() {
			t.Errorf("%s: object is nil", name)
		}
	}
}
