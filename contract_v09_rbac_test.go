// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/neverlless/goipa"
)

const (
	builtinRole       = "User Administrator"
	builtinPrivilege  = "User Administrators"
	builtinPermission = "System: Add Users"
)

// TestContractRBACBuiltins pins the role, privilege and permission every
// FreeIPA ships, and their links to each other.
func TestContractRBACBuiltins(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		r, err := b.admin.RoleShow(builtinRole)
		if err != nil {
			t.Fatal(err)
		}
		if r.Name != builtinRole || r.Description != "Responsible for creating Users and Groups" || !slices.Contains(r.Privileges, builtinPrivilege) {
			t.Errorf("role %+v", r)
		}
		p, err := b.admin.PrivilegeShow(builtinPrivilege)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name != builtinPrivilege || p.Description != "User Administrators" || !slices.Contains(p.Permissions, builtinPermission) || !slices.Contains(p.Roles, builtinRole) {
			t.Errorf("privilege %+v", p)
		}
		perm, err := b.admin.PermissionShow(builtinPermission)
		if err != nil {
			t.Fatal(err)
		}
		if perm.Name != builtinPermission || !slices.Equal(perm.Rights, []string{"add"}) || perm.Type != "user" ||
			perm.BindType != "permission" || perm.Location == "" || !slices.Contains(perm.Privileges, builtinPrivilege) {
			t.Errorf("permission %+v", perm)
		}
	})
}

func TestContractRBACFind(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		roles, err := b.admin.RoleFind(ipa.Options{"cn": builtinRole})
		if err != nil || len(roles) != 1 || roles[0].Name != builtinRole || !slices.Contains(roles[0].Privileges, builtinPrivilege) {
			t.Errorf("RoleFind: %v %+v", err, roles)
		}
		privs, err := b.admin.PrivilegeFind(ipa.Options{"cn": builtinPrivilege})
		if err != nil || len(privs) != 1 || !slices.Contains(privs[0].Permissions, builtinPermission) {
			t.Errorf("PrivilegeFind: %v %+v", err, privs)
		}
		perms, err := b.admin.PermissionFind(ipa.Options{"cn": builtinPermission})
		if err != nil || len(perms) != 1 || perms[0].Type != "user" || !slices.Contains(perms[0].Privileges, builtinPrivilege) {
			t.Errorf("PermissionFind: %v %+v", err, perms)
		}
	})
}

// TestContractRBACNotFound pins S2 for the three objects.
func TestContractRBACNotFound(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		name := "gtr" + randHex(t, 4)
		_, err := b.admin.RoleShow(name)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = b.admin.PrivilegeShow(name)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = b.admin.PermissionShow(name)
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// TestContractRoleMembers reads back a role made through RPC.
func TestContractRoleMembers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		name := "gtr" + randHex(t, 4)
		uid := newUserWithPassword(t, b, goodPW)
		mustRPC(t, b.admin, "role_add", []string{name}, ipa.Options{"description": "contract"})
		t.Cleanup(func() { _, _ = b.admin.RPC("role_del", []string{name}, nil) })
		missing := "gtnosuch" + randHex(t, 4)
		res := mustRPC(t, b.admin, "role_add_member", []string{name}, ipa.Options{"user": []string{uid, missing}})
		var failed struct{ Member struct{ User [][]string } }
		if err := json.Unmarshal(res.Result.Failed, &failed); err != nil {
			t.Fatal(err)
		}
		if res.Result.Completed != 1 || !reflect.DeepEqual(failed.Member.User, [][]string{{missing, "no such entry"}}) {
			t.Errorf("completed %d, failed %s", res.Result.Completed, res.Result.Failed)
		}
		r, err := b.admin.RoleShow(name)
		if err != nil {
			t.Fatal(err)
		}
		if r.Description != "contract" || !slices.Equal(r.Users, []string{uid}) || len(r.Privileges) != 0 {
			t.Errorf("role %+v", r)
		}
		mustRPC(t, b.admin, "role_del", []string{name}, nil)
		_, err = b.admin.RoleShow(name)
		wantIs(t, err, ipa.ErrNotFound)
	})
}

// TestContractRBACPlainUser pins Q122: the RBAC read permissions are bound
// to the RBAC Readers privilege, so a plain user sees no roles, privileges
// or permissions.
func TestContractRBACPlainUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		plain := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		_, err := plain.RoleShow(builtinRole)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = plain.PermissionShow(builtinPermission)
		wantIs(t, err, ipa.ErrNotFound)
		roles, err := plain.RoleFind(nil)
		if err != nil || len(roles) != 0 {
			t.Errorf("RoleFind = %d roles, %v; want none", len(roles), err)
		}
	})
}
