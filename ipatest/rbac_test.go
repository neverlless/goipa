// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"slices"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func TestRBAC_SeedsAndShow(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	c := s.ClientAs("admin")

	r, err := c.RoleShow("User Administrator")
	if err != nil || r.Description != "Responsible for creating Users and Groups" || !slices.Contains(r.Privileges, "User Administrators") {
		t.Errorf("role = %+v, %v", r, err)
	}
	p, err := c.PrivilegeShow("User Administrators")
	if err != nil || !slices.Equal(p.Roles, []string{"User Administrator"}) || !slices.Contains(p.Permissions, "System: Add Users") {
		t.Errorf("privilege = %+v, %v", p, err)
	}
	perm, err := c.PermissionShow("System: Add Users")
	if err != nil || perm.Type != "user" || perm.BindType != "permission" || !slices.Equal(perm.Rights, []string{"add"}) ||
		!slices.Equal(perm.Privileges, []string{"User Administrators"}) {
		t.Errorf("permission = %+v, %v", perm, err)
	}
	all := gjson.ParseBytes(rpc(t, c, "permission_show", []string{"System: Add Users"}, ipa.Options{"all": true}).Result.Data)
	if all.Get("dn").String() != "cn=System: Add Users,cn=permissions,cn=pbac,dc=test,dc=local" || all.Get("objectclass.3").String() != "ipapermissionv2" {
		t.Errorf("permission all = %s", all.Raw)
	}
	noMembers := gjson.ParseBytes(rpc(t, c, "privilege_show", []string{"User Administrators"}, ipa.Options{"no_members": true}).Result.Data)
	if noMembers.Get("member_role").Exists() {
		t.Errorf("privilege no_members = %s", noMembers.Raw)
	}

	// Q122: without the read privilege the entries do not exist.
	b := s.ClientAs("bob")
	_, err = b.RoleShow("User Administrator")
	wantIpaCode(t, "non-admin role_show", err, ipa.CodeNotFound)
	if list, err := b.PermissionFind(nil); err != nil || len(list) != 0 {
		t.Errorf("non-admin permission_find = %+v, %v", list, err)
	}
	_, err = c.PrivilegeShow("none")
	wantIpaCode(t, "missing privilege", err, ipa.CodeNotFound)
}

func TestRBAC_SeedAndGetters(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddRole("Helpdesk", ipa.Role{Name: "ignored", Description: "first line", Users: []string{"bob"}, Privileges: []string{"Reset"}})
	s.AddPrivilege("Reset", ipa.Privilege{Description: "password reset", Permissions: []string{"Reset PW"}, Roles: []string{"Helpdesk"}})
	s.AddPermission("Reset PW", ipa.Permission{Rights: []string{"write"}, Type: "user", Attrs: []string{"userpassword"},
		TargetGroup: "staff", Privileges: []string{"Reset"}})

	r, ok := s.Role("Helpdesk")
	if !ok || r.Name != "Helpdesk" || !slices.Equal(r.Users, []string{"bob"}) {
		t.Errorf("Role = %+v, %v", r, ok)
	}
	r.Users[0] = "changed"
	if r, _ := s.Role("Helpdesk"); r.Users[0] != "bob" {
		t.Error("Role returned shared storage")
	}
	if p, ok := s.Privilege("Reset"); !ok || p.Name != "Reset" || !slices.Equal(p.Roles, []string{"Helpdesk"}) {
		t.Errorf("Privilege = %+v, %v", p, ok)
	}
	if p, ok := s.Permission("Reset PW"); !ok || p.Name != "Reset PW" || p.TargetGroup != "staff" {
		t.Errorf("Permission = %+v, %v", p, ok)
	}
	for _, ok := range []bool{func() bool { _, ok := s.Role("x"); return ok }(), func() bool { _, ok := s.Privilege("x"); return ok }(),
		func() bool { _, ok := s.Permission("x"); return ok }()} {
		if ok {
			t.Error("getter found a missing entry")
		}
	}

	c := s.ClientAs("admin")
	perm, err := c.PermissionShow("Reset PW")
	if err != nil || !slices.Equal(perm.Attrs, []string{"userpassword"}) || perm.TargetGroup != "staff" {
		t.Errorf("permission_show = %+v, %v", perm, err)
	}
	for _, tc := range []struct {
		opts ipa.Options
		want int
	}{{nil, 2}, {ipa.Options{"type": "user"}, 2}, {ipa.Options{"cn": "reset pw"}, 1}, {ipa.Options{"type": "group"}, 0}} {
		if list, err := c.PermissionFind(tc.opts); err != nil || len(list) != tc.want {
			t.Errorf("permission_find %v = %d, %v; want %d", tc.opts, len(list), err, tc.want)
		}
	}
	if list, err := c.RoleFind(ipa.Options{"description": "first line"}); err != nil || len(list) != 1 || list[0].Name != "Helpdesk" {
		t.Errorf("role_find = %+v, %v", list, err)
	}
	if got := cns(rpc(t, c, "privilege_find", []string{"RESET"}, nil)); !slices.Equal(got, []string{"Reset"}) {
		t.Errorf("privilege_find needle = %v", got)
	}
	if got := cns(rpc(t, c, "role_find", []string{"zzz"}, nil)); len(got) != 0 {
		t.Errorf("role_find no match = %v", got)
	}
	res := gjson.ParseBytes(rpc(t, c, "role_find", []string{"helpdesk"}, ipa.Options{"no_members": false}).Result.Data)
	if res.Get("0.member_user").Raw != `["bob"]` {
		t.Errorf("role_find members = %s", res.Raw)
	}
}

func TestRole_AddMemberDel(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	s.AddGroup("ops", ipatest.Group{})
	s.AddHost("h.test.local", ipatest.Host{})
	c := s.ClientAs("admin")
	rpc(t, c, "role_add", []string{"Helpdesk"}, ipa.Options{"description": "first line"})
	_, err := c.RPC("role_add", []string{"Helpdesk"}, nil)
	wantIpaCode(t, "duplicate role", err, ipa.CodeDuplicateEntry)

	res := gjson.ParseBytes(rpc(t, c, "role_add_member", []string{"Helpdesk"}, ipa.Options{
		"user": []string{"bob", "ghost"}, "group": []string{"ops"}, "host": []string{"h.test.local"},
		"hostgroup": []string{"any"}, "service": []string{"HTTP/h.test.local"},
	}).Result.Raw)
	if res.Get("completed").Int() != 3 || res.Get("failed.member.user").Raw != `[["ghost","no such entry"]]` ||
		res.Get("failed.member.hostgroup.0.1").String() != "no such entry" || res.Get("failed.member.service.0.1").String() != "no such entry" {
		t.Errorf("add_member = %s", res.Raw)
	}
	res = gjson.ParseBytes(rpc(t, c, "role_add_member", []string{"Helpdesk"}, ipa.Options{"user": []string{"bob"}}).Result.Raw)
	if res.Get("failed.member.user").Raw != `[["bob","This entry is already a member"]]` {
		t.Errorf("add_member twice = %s", res.Raw)
	}
	if r, _ := s.Role("Helpdesk"); !slices.Equal(r.Users, []string{"bob"}) || !slices.Equal(r.Groups, []string{"ops"}) || !slices.Equal(r.Hosts, []string{"h.test.local"}) {
		t.Errorf("stored role = %+v", r)
	}
	_, err = c.RPC("role_add_member", []string{"none"}, ipa.Options{"user": []string{"bob"}})
	wantIpaCode(t, "add_member missing role", err, ipa.CodeNotFound)
	_, err = c.RPC("role_add_member", nil, nil)
	wantIpaCode(t, "add_member without cn", err, ipa.CodeRequirement)

	_, err = c.RPC("role_del", []string{"Helpdesk", "none"}, nil)
	wantIpaCode(t, "del with a missing role", err, ipa.CodeNotFound)
	if _, ok := s.Role("Helpdesk"); !ok {
		t.Error("failed role_del removed a role")
	}
	rpc(t, c, "role_del", []string{"Helpdesk"}, nil)
	if _, ok := s.Role("Helpdesk"); ok {
		t.Error("role survived role_del")
	}
}

func TestPwPolicy_Commands(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddGroup("staff", ipatest.Group{})
	s.AddGroup("ops", ipatest.Group{MemberGroups: []string{"staff"}})
	s.AddUser("bob", ipatest.User{Groups: []string{"staff"}})
	s.AddUser("nopol", ipatest.User{})
	c := s.ClientAs("admin")

	g, err := c.PwPolicyShow("")
	if err != nil || g.Name != "global_policy" || g.MaxLife != 90*24*time.Hour || g.MinLength != 8 || g.GraceLimit != -1 || g.DictCheck {
		t.Errorf("global = %+v, %v", g, err)
	}
	_, err = c.RPC("pwpolicy_show", nil, ipa.Options{"bogus": 1})
	wantIpaCode(t, "unknown option", err, ipa.CodeOption)
	_, err = c.PwPolicyShow("staff")
	wantIpaCode(t, "missing policy", err, ipa.CodeNotFound)

	_, err = c.RPC("pwpolicy_add", nil, nil)
	wantIpaCode(t, "add without group", err, ipa.CodeRequirement)
	_, err = c.RPC("pwpolicy_add", []string{"nogroup"}, ipa.Options{"cospriority": 1})
	wantIpaCode(t, "add for a missing group", err, ipa.CodeNotFound)
	_, err = c.RPC("pwpolicy_add", []string{"staff"}, nil)
	wantIpaCode(t, "add without priority", err, ipa.CodeRequirement)
	rpc(t, c, "pwpolicy_add", []string{"staff"}, ipa.Options{"cospriority": 5, "krbmaxpwdlife": "30", "krbminpwdlife": []any{"2"},
		"krbpwdlockoutduration": 120, "krbpwdminlength": 12, "ipapwddictcheck": true, "ipapwdusercheck": "TRUE"})
	_, err = c.RPC("pwpolicy_add", []string{"staff"}, ipa.Options{"cospriority": 5})
	wantIpaCode(t, "duplicate add", err, ipa.CodeDuplicateEntry)
	want := ipatest.PwPolicy{Priority: 5, MaxLife: 30 * 24 * time.Hour, MinLife: 2 * time.Hour, LockoutDuration: 2 * time.Minute,
		MinLength: 12, DictCheck: true, UserCheck: true, GraceLimit: -1}
	if got, ok := s.PwPolicy("staff"); !ok || got != want {
		t.Errorf("stored = %+v, want %+v", got, want)
	}
	if p, err := c.PwPolicyShow("staff"); err != nil || p.Priority != 5 || p.MaxLife != want.MaxLife || !p.UserCheck || p.HistoryLength != 0 {
		t.Errorf("show = %+v, %v", p, err)
	}

	s.SetPwPolicy("ops", ipatest.PwPolicy{Priority: 1, MinLength: 20})
	if p, err := c.UserPwPolicy("bob"); err != nil || p.Name != "ops" || p.MinLength != 20 || p.Priority != 0 {
		t.Errorf("bob's policy = %+v, %v", p, err) // ops (priority 1) wins through nesting; no cospriority for the effective one
	}
	if p, err := c.UserPwPolicy("nopol"); err != nil || p.Name != "global_policy" {
		t.Errorf("nopol's policy = %+v, %v", p, err)
	}
	_, err = c.UserPwPolicy("ghost")
	wantIpaCode(t, "missing user", err, ipa.CodeNotFound)
	if _, err := s.ClientAs("bob").PwPolicyShow("staff"); err == nil || err.Error() != "ipa: error 4001 - staff: password policy not found" {
		t.Errorf("non-admin show (Q32): %v", err)
	}
	if _, err := s.ClientAs("bob").PwPolicyShow(""); err == nil || err.Error() != "ipa: error 4001 - None: password policy not found" {
		t.Errorf("non-admin global show (Q32): %v", err)
	}

	for _, args := range [][]string{{"global_policy"}, {"staff", "none"}} {
		_, err := c.RPC("pwpolicy_del", args, nil)
		wantIpaCode(t, "del "+args[0], err, ipa.CodeNotFound)
	}
	rpc(t, c, "pwpolicy_del", []string{"staff", "ops"}, nil)
	if _, ok := s.PwPolicy("staff"); ok {
		t.Error("policy survived pwpolicy_del")
	}
	_, err = c.PwPolicyShow("staff")
	wantIpaCode(t, "show after del", err, ipa.CodeNotFound)
}
