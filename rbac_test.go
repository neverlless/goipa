// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestRBACShow_Seeded(t *testing.T) {
	s, c := newFake(t)
	s.AddRole("r", ipa.Role{Description: "d", Users: []string{"u"}, Groups: []string{"g"}, Hosts: []string{"h"},
		HostGroups: []string{"hg"}, Services: []string{"svc"}, Privileges: []string{"p"}})
	s.AddPrivilege("p", ipa.Privilege{Description: "pd", Permissions: []string{"perm"}, Roles: []string{"r"}})
	s.AddPermission("perm", ipa.Permission{Rights: []string{"read", "search"}, Type: "group", Attrs: []string{"cn"},
		BindType: "all", Location: "cn=x", Filters: []string{"(f=1)"}, TargetGroup: "tg", Privileges: []string{"p"}})

	r, err := c.RoleShow("r")
	if want := (&ipa.Role{Name: "r", Description: "d", Users: []string{"u"}, Groups: []string{"g"}, Hosts: []string{"h"},
		HostGroups: []string{"hg"}, Services: []string{"svc"}, Privileges: []string{"p"}}); err != nil || !reflect.DeepEqual(r, want) {
		t.Errorf("RoleShow: %v %+v", err, r)
	}
	p, err := c.PrivilegeShow("p")
	if want := (&ipa.Privilege{Name: "p", Description: "pd", Permissions: []string{"perm"}, Roles: []string{"r"}}); err != nil || !reflect.DeepEqual(p, want) {
		t.Errorf("PrivilegeShow: %v %+v", err, p)
	}
	perm, err := c.PermissionShow("perm")
	if want := (&ipa.Permission{Name: "perm", Rights: []string{"read", "search"}, Type: "group", Attrs: []string{"cn"},
		BindType: "all", Location: "cn=x", Filters: []string{"(f=1)"}, TargetGroup: "tg", Privileges: []string{"p"}}); err != nil || !reflect.DeepEqual(perm, want) {
		t.Errorf("PermissionShow: %v %+v", err, perm)
	}
}

func TestRBACShow_EmptyName(t *testing.T) {
	s, c := newFake(t)
	for name, f := range map[string]func() error{
		"role":       func() error { _, err := c.RoleShow(""); return err },
		"privilege":  func() error { _, err := c.PrivilegeShow(""); return err },
		"permission": func() error { _, err := c.PermissionShow(""); return err },
	} {
		if err := f(); err == nil || err.Error() != "ipa: "+name+" name is required" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestRBACFind_Criteria(t *testing.T) {
	s, c := newFake(t)
	s.AddRole("alpha", ipa.Role{Description: "first"})
	s.AddRole("beta", ipa.Role{Description: "second"})
	roles, err := c.RoleFind(ipa.Options{"cn": "beta"})
	if err != nil || len(roles) != 1 || roles[0].Name != "beta" {
		t.Errorf("RoleFind cn: %v %+v", err, roles)
	}
	all, err := c.RoleFind(nil)
	if err != nil || len(all) < 3 { // alpha, beta and the builtin
		t.Errorf("RoleFind all: %v %d", err, len(all))
	}
	perms, err := c.PermissionFind(ipa.Options{"type": "user"})
	if err != nil || len(perms) == 0 {
		t.Errorf("PermissionFind type: %v %+v", err, perms)
	}
	for _, p := range perms {
		if p.Type != "user" {
			t.Errorf("type filter returned %+v", p)
		}
	}
	calls := s.Calls()
	if c := calls[0]; c.Method != "role_find" || len(c.Args) != 1 || c.Args[0] != "" || c.Options["all"] != true || c.Options["no_members"] != false {
		t.Errorf("call %+v", c)
	}
}
