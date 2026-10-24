// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
)

// newHBACRule adds an HBAC rule and deletes it when the test ends.
func newHBACRule(t *testing.T, b backend, r ipa.HBACRule) *ipa.HBACRule {
	t.Helper()
	r.Name = "gr" + randHex(t, 4)
	got, err := b.admin.HBACRuleAdd(&r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.HBACRuleDelete(r.Name) })
	return got
}

func TestContractHBACRuleLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		added := newHBACRule(t, b, ipa.HBACRule{Description: "goipa test", UserCategory: "all"})
		if !added.Enabled || added.UserCategory != "all" || added.HostCategory != "" || added.Description != "goipa test" {
			t.Errorf("added = %+v", added)
		}
		got, err := b.admin.HBACRuleShow(added.Name)
		if err != nil || !reflect.DeepEqual(got, added) {
			t.Errorf("show = %+v, %v; want %+v", got, err, added)
		}
		if err := b.admin.HBACRuleDelete(added.Name); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.HBACRuleShow(added.Name)
		wantIs(t, err, ipa.ErrNotFound)
		wantIs(t, b.admin.HBACRuleDelete(added.Name), ipa.ErrNotFound)
	})
}

// TestContractHBACRuleEnableDisable pins Q71.
func TestContractHBACRuleEnableDisable(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		r := newHBACRule(t, b, ipa.HBACRule{})
		if err := b.admin.HBACRuleDisable(r.Name); err != nil {
			t.Fatal(err)
		}
		if got, err := b.admin.HBACRuleShow(r.Name); err != nil || got.Enabled {
			t.Fatalf("after disable = %+v, %v", got, err)
		}
		if err := b.admin.HBACRuleDisable(r.Name); err != nil {
			t.Errorf("disable twice: %v", err)
		}
		if err := b.admin.HBACRuleEnable(r.Name); err != nil {
			t.Fatal(err)
		}
		if got, err := b.admin.HBACRuleShow(r.Name); err != nil || !got.Enabled {
			t.Fatalf("after enable = %+v, %v", got, err)
		}
		if err := b.admin.HBACRuleEnable(r.Name); err != nil {
			t.Errorf("enable twice: %v", err)
		}
		wantIs(t, b.admin.HBACRuleEnable("nosuchrule-"+randHex(t, 4)), ipa.ErrNotFound)
	})
}

func TestContractHBACRuleMembers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		gid := "gg" + randHex(t, 4)
		if _, err := b.admin.GroupAdd(&ipa.Group{Name: gid}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.GroupDelete(gid) })
		host := serverHost(t, b)
		r := newHBACRule(t, b, ipa.HBACRule{})

		got, err := b.admin.HBACRuleAddUser(r.Name, []string{uid}, []string{gid})
		if err != nil || !reflect.DeepEqual(got.Users, []string{uid}) || !reflect.DeepEqual(got.Groups, []string{gid}) {
			t.Fatalf("add user = %+v, %v", got, err)
		}
		got, err = b.admin.HBACRuleAddHost(r.Name, []string{host}, nil)
		if err != nil || !reflect.DeepEqual(got.Hosts, []string{host}) {
			t.Fatalf("add host = %+v, %v", got, err)
		}
		got, err = b.admin.HBACRuleAddService(r.Name, []string{"sshd"}, []string{"Sudo"})
		if err != nil || !reflect.DeepEqual(got.Services, []string{"sshd"}) || !reflect.DeepEqual(got.ServiceGroups, []string{"Sudo"}) {
			t.Fatalf("add service = %+v, %v", got, err)
		}
		if shown, err := b.admin.HBACRuleShow(r.Name); err != nil || !reflect.DeepEqual(shown, got) {
			t.Errorf("show = %+v, %v; want %+v", shown, err, got)
		}

		got, err = b.admin.HBACRuleRemoveUser(r.Name, []string{uid}, []string{gid})
		if err != nil || got.Users != nil || got.Groups != nil {
			t.Fatalf("remove user = %+v, %v", got, err)
		}
		got, err = b.admin.HBACRuleRemoveHost(r.Name, []string{host}, nil)
		if err != nil || got.Hosts != nil {
			t.Fatalf("remove host = %+v, %v", got, err)
		}
		got, err = b.admin.HBACRuleRemoveService(r.Name, []string{"sshd"}, []string{"Sudo"})
		if err != nil || got.Services != nil || got.ServiceGroups != nil {
			t.Fatalf("remove service = %+v, %v", got, err)
		}
	})
}

// TestContractHBACRuleMemberMissing pins Q72.
func TestContractHBACRuleMemberMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		r := newHBACRule(t, b, ipa.HBACRule{})
		ghost := "nosuch" + randHex(t, 4)
		check := func(what string, got *ipa.HBACRule, err error, typ, msg string) {
			t.Helper()
			var me *ipa.MemberError
			if !errors.As(err, &me) || got == nil || got.Name != r.Name {
				t.Fatalf("%s = %+v, %v; want the rule and *MemberError", what, got, err)
			}
			if len(me.Failures) != 1 || me.Failures[0].Type != typ || me.Failures[0].Name != ghost || me.Failures[0].Message != msg {
				t.Errorf("%s failures = %+v", what, me.Failures)
			}
		}
		got, err := b.admin.HBACRuleAddUser(r.Name, []string{ghost}, nil)
		check("add user", got, err, "user", "no such entry")
		got, err = b.admin.HBACRuleAddHost(r.Name, nil, []string{ghost})
		check("add hostgroup", got, err, "hostgroup", "no such entry")
		got, err = b.admin.HBACRuleAddService(r.Name, []string{ghost}, nil)
		check("add service", got, err, "hbacsvc", "no such entry")
		got, err = b.admin.HBACRuleRemoveService(r.Name, nil, []string{ghost})
		check("remove service group", got, err, "hbacsvcgroup", "This entry is not a member")

		got, err = b.admin.HBACRuleAddService(r.Name, []string{"sshd"}, nil)
		if err != nil {
			t.Fatal(got, err)
		}
		_, err = b.admin.HBACRuleAddService(r.Name, []string{"sshd"}, nil)
		var me *ipa.MemberError
		if !errors.As(err, &me) || me.Failures[0].Message != "This entry is already a member" {
			t.Errorf("duplicate = %v", err)
		}
		_, err = b.admin.HBACRuleRemoveService(r.Name, []string{"login"}, nil)
		if !errors.As(err, &me) || me.Failures[0].Message != "This entry is not a member" {
			t.Errorf("not a member = %v", err)
		}
		_, err = b.admin.HBACRuleAddUser("nosuchrule-"+randHex(t, 4), []string{"admin"}, nil)
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// TestContractHBACRuleCategoryConflict pins Q73.
func TestContractHBACRuleCategoryConflict(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		r := newHBACRule(t, b, ipa.HBACRule{UserCategory: "all", HostCategory: "all", ServiceCategory: "all"})
		_, err := b.admin.HBACRuleAddUser(r.Name, []string{"admin"}, nil)
		wantCode(t, "category", err, 4303)
		if err == nil || err.Error() != "ipa: error 4303 - users cannot be added when user category='all'" {
			t.Errorf("user: %q", err)
		}
		_, err = b.admin.HBACRuleAddHost(r.Name, []string{serverHost(t, b)}, nil)
		wantCode(t, "category", err, 4303)
		if err == nil || err.Error() != "ipa: error 4303 - hosts cannot be added when host category='all'" {
			t.Errorf("host: %q", err)
		}
		_, err = b.admin.HBACRuleAddService(r.Name, []string{"sshd"}, nil)
		wantCode(t, "category", err, 4303)
		if err == nil || err.Error() != "ipa: error 4303 - services cannot be added when service category='all'" {
			t.Errorf("service: %q", err)
		}
	})
}

func TestContractHBACRuleWithTest(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		host := serverHost(t, b)
		r := newHBACRule(t, b, ipa.HBACRule{})
		if _, err := b.admin.HBACRuleAddHost(r.Name, []string{host}, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.HBACRuleAddService(r.Name, []string{"sshd"}, nil); err != nil {
			t.Fatal(err)
		}
		if got, err := b.admin.HBACTest(uid, host, "sshd", r.Name); err != nil || got.Granted {
			t.Fatalf("before = %+v, %v", got, err)
		}
		if _, err := b.admin.HBACRuleAddUser(r.Name, []string{uid}, nil); err != nil {
			t.Fatal(err)
		}
		got, err := b.admin.HBACTest(uid, host, "sshd", r.Name)
		if err != nil || !got.Granted || !reflect.DeepEqual(got.Matched, []string{r.Name}) {
			t.Fatalf("after = %+v, %v", got, err)
		}
		if got, err := b.admin.HBACTest(uid, host, "login", r.Name); err != nil || got.Granted {
			t.Errorf("other service = %+v, %v", got, err)
		}
	})
}
