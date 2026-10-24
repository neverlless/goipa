// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// newSudoRule adds an empty sudo rule and deletes it when the test ends.
func newSudoRule(t *testing.T, b backend) string {
	t.Helper()
	cn := "gs" + randHex(t, 4)
	if _, err := b.admin.SudoRuleAdd(&ipa.SudoRule{Name: cn}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.SudoRuleDelete(cn) })
	return cn
}

// newSudoCmd adds a sudo command; register it before the rules that use it,
// so the cleanup removes the rules first.
func newSudoCmd(t *testing.T, b backend) string {
	t.Helper()
	cmd := "/usr/bin/goipa" + randHex(t, 4)
	mustRPC(t, b.admin, "sudocmd_add", []string{cmd}, nil)
	t.Cleanup(func() { _, _ = b.admin.RPC("sudocmd_del", []string{cmd}, nil) })
	return cmd
}

func newSudoUser(t *testing.T, b backend) string {
	t.Helper()
	uid := newUID(t, b)
	if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
		t.Fatal(err)
	}
	return uid
}

func TestContractSudoRuleLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := "gs" + randHex(t, 4)
		// sudoorder must be unique on the server
		n, _ := strconv.ParseUint(randHex(t, 2), 16, 32)
		order := 1000 + int(n)
		in := &ipa.SudoRule{Name: cn, Description: "goipa test", Order: order, Enabled: false,
			HostCategory: "all", CmdCategory: "all", RunAsUserCategory: "all", RunAsGroupCategory: "all"}
		got, err := b.admin.SudoRuleAdd(in)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.SudoRuleDelete(cn) })
		want := &ipa.SudoRule{Name: cn, Description: "goipa test", Order: order, Enabled: true,
			HostCategory: "all", CmdCategory: "all", RunAsUserCategory: "all", RunAsGroupCategory: "all"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("add = %+v\nwant  %+v", got, want)
		}
		got, err = b.admin.SudoRuleShow(cn)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("show = %+v, %v", got, err)
		}
		if err := b.admin.SudoRuleDelete(cn); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.SudoRuleShow(cn)
		wantIs(t, err, ipa.ErrNotFound)
		wantIs(t, b.admin.SudoRuleDelete(cn), ipa.ErrNotFound)
	})
}

// Q80
func TestContractSudoRuleEnableTwice(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newSudoRule(t, b)
		for _, step := range []struct {
			name string
			call func(string) error
			want bool
		}{
			{"disable", b.admin.SudoRuleDisable, false},
			{"disable again", b.admin.SudoRuleDisable, false},
			{"enable", b.admin.SudoRuleEnable, true},
			{"enable again", b.admin.SudoRuleEnable, true},
		} {
			if err := step.call(cn); err != nil {
				t.Fatalf("%s: %v", step.name, err)
			}
			r, err := b.admin.SudoRuleShow(cn)
			if err != nil || r.Enabled != step.want {
				t.Fatalf("%s: rule = %+v, %v", step.name, r, err)
			}
		}
		wantIs(t, b.admin.SudoRuleEnable("gsmissing"+randHex(t, 4)), ipa.ErrNotFound)
	})
}

func TestContractSudoRuleUsersHosts(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid, g, host := newSudoUser(t, b), newGroup(t, b), serverHost(t, b)
		cn := newSudoRule(t, b)
		r, err := b.admin.SudoRuleAddUser(cn, []string{uid}, []string{g})
		if err != nil || !reflect.DeepEqual(r.Users, []string{uid}) || !reflect.DeepEqual(r.Groups, []string{g}) {
			t.Fatalf("add user = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleAddHost(cn, []string{host}, nil)
		if err != nil || !reflect.DeepEqual(r.Hosts, []string{host}) {
			t.Fatalf("add host = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleRemoveUser(cn, []string{uid}, []string{g})
		if err != nil || r.Users != nil || r.Groups != nil {
			t.Fatalf("remove user = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleRemoveHost(cn, []string{host}, nil)
		if err != nil || r.Hosts != nil {
			t.Fatalf("remove host = %+v, %v", r, err)
		}
	})
}

func TestContractSudoRuleCommands(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		allow, deny := newSudoCmd(t, b), newSudoCmd(t, b)
		cn := newSudoRule(t, b)
		r, err := b.admin.SudoRuleAddAllowCommand(cn, []string{allow}, nil)
		if err != nil || !reflect.DeepEqual(r.AllowCommands, []string{allow}) {
			t.Fatalf("add allow = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleAddDenyCommand(cn, []string{deny}, nil)
		if err != nil || !reflect.DeepEqual(r.DenyCommands, []string{deny}) || !reflect.DeepEqual(r.AllowCommands, []string{allow}) {
			t.Fatalf("add deny = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleRemoveAllowCommand(cn, []string{allow}, nil)
		if err != nil || r.AllowCommands != nil {
			t.Fatalf("remove allow = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleRemoveDenyCommand(cn, []string{deny}, nil)
		if err != nil || r.DenyCommands != nil {
			t.Fatalf("remove deny = %+v, %v", r, err)
		}
	})
}

func TestContractSudoRuleRunAs(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid, g := newSudoUser(t, b), newGroup(t, b)
		cn := newSudoRule(t, b)
		r, err := b.admin.SudoRuleAddRunAsUser(cn, []string{uid}, []string{g})
		if err != nil || !reflect.DeepEqual(r.RunAsUsers, []string{uid}) || !reflect.DeepEqual(r.RunAsUserGroups, []string{g}) {
			t.Fatalf("add runasuser = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleAddRunAsGroup(cn, []string{g})
		if err != nil || !reflect.DeepEqual(r.RunAsGroups, []string{g}) {
			t.Fatalf("add runasgroup = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleRemoveRunAsUser(cn, []string{uid}, []string{g})
		if err != nil || r.RunAsUsers != nil || r.RunAsUserGroups != nil {
			t.Fatalf("remove runasuser = %+v, %v", r, err)
		}
		r, err = b.admin.SudoRuleRemoveRunAsGroup(cn, []string{g})
		if err != nil || r.RunAsGroups != nil {
			t.Fatalf("remove runasgroup = %+v, %v", r, err)
		}
	})
}

// Q82
func TestContractSudoRuleOptions(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newSudoRule(t, b)
		r, err := b.admin.SudoRuleAddOption(cn, "!authenticate")
		if err != nil || !reflect.DeepEqual(r.Options, []string{"!authenticate"}) {
			t.Fatalf("add option = %+v, %v", r, err)
		}
		_, err = b.admin.SudoRuleAddOption(cn, "!authenticate")
		wantCode(t, "add option twice", err, ipa.CodeDuplicateEntry)
		r, err = b.admin.SudoRuleRemoveOption(cn, "!authenticate")
		if err != nil || r.Options != nil {
			t.Fatalf("remove option = %+v, %v", r, err)
		}
		_, err = b.admin.SudoRuleRemoveOption(cn, "!authenticate")
		wantCode(t, "remove unset option", err, ipa.CodeAttrValueNotFound)
		t.Logf("remove unset option: %v", err)
	})
}

// Q81
func TestContractSudoRuleMemberMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newSudoRule(t, b)
		ghost := "/usr/bin/goipa-missing" + randHex(t, 4)
		r, err := b.admin.SudoRuleAddAllowCommand(cn, []string{ghost}, nil)
		var me *ipa.MemberError
		if !errors.As(err, &me) || r == nil || r.Name != cn {
			t.Fatalf("rule = %+v, err = %v", r, err)
		}
		want := []ipa.MemberFailure{{Kind: "memberallowcmd", Type: "sudocmd", Name: ghost, Message: "no such entry"}}
		if !reflect.DeepEqual(me.Failures, want) {
			t.Errorf("failures = %+v", me.Failures)
		}
		r, err = b.admin.SudoRuleRemoveAllowCommand(cn, []string{ghost}, nil)
		want[0].Message = "This entry is not a member"
		if !errors.As(err, &me) || r == nil || !reflect.DeepEqual(me.Failures, want) {
			t.Errorf("remove missing: rule = %+v, err = %v", r, err)
		}
		_, err = b.admin.SudoRuleAddUser("gsmissing"+randHex(t, 4), []string{"admin"}, nil)
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// Q81
func TestContractSudoRuleExternalMembers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newSudoRule(t, b)
		ghost := "gtghost" + randHex(t, 4)
		r, err := b.admin.SudoRuleAddUser(cn, []string{ghost}, nil)
		if err != nil || r.Users != nil {
			t.Fatalf("add unknown user = %+v, %v", r, err)
		}
		res := mustRPC(t, b.admin, "sudorule_show", []string{cn}, nil)
		if got := gjson.GetBytes(res.Result.Data, "externaluser").Raw; got != `["`+ghost+`"]` {
			t.Errorf("externaluser = %s", got)
		}
		if _, err := b.admin.SudoRuleRemoveUser(cn, []string{ghost}, nil); err != nil {
			t.Fatal(err)
		}
		res = mustRPC(t, b.admin, "sudorule_show", []string{cn}, nil)
		if gjson.GetBytes(res.Result.Data, "externaluser.0").Exists() {
			t.Errorf("externaluser left: %s", res.Result.Data)
		}
	})
}
