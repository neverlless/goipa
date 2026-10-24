// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
)

// Role is a FreeIPA role: the privileges it grants and who holds it.
// Change attributes with Modify("role_mod", …).
type Role struct {
	// cn, description
	Name, Description string
	// member_user, member_group, member_host, member_hostgroup, member_service
	Users, Groups, Hosts, HostGroups, Services []string
	// memberof_privilege
	Privileges []string
}

// Privilege is a FreeIPA privilege: a named set of permissions.
// Change attributes with Modify("privilege_mod", …).
type Privilege struct {
	// cn, description
	Name, Description string
	// memberof_permission
	Permissions []string
	// member_role
	Roles []string
}

// Permission is a FreeIPA permission, the unit of access control.
// Change attributes with Modify("permission_mod", …).
type Permission struct {
	// cn
	Name string
	// ipapermright
	Rights []string
	// type
	Type string
	// attrs
	Attrs []string
	// ipapermbindruletype
	BindType string
	// ipapermlocation
	Location string
	// ipapermtargetfilter
	Filters []string
	// targetgroup
	TargetGroup string
	// member_privilege
	Privileges []string
}

func roleFrom(e Entry) *Role {
	return &Role{
		Name:        e.Str("cn"),
		Description: e.Str("description"),
		Users:       e.Strs("member_user"),
		Groups:      e.Strs("member_group"),
		Hosts:       e.Strs("member_host"),
		HostGroups:  e.Strs("member_hostgroup"),
		Services:    e.Strs("member_service"),
		Privileges:  e.Strs("memberof_privilege"),
	}
}

func privilegeFrom(e Entry) *Privilege {
	return &Privilege{
		Name:        e.Str("cn"),
		Description: e.Str("description"),
		Permissions: e.Strs("memberof_permission"),
		Roles:       e.Strs("member_role"),
	}
}

func permissionFrom(e Entry) *Permission {
	return &Permission{
		Name:        e.Str("cn"),
		Rights:      e.Strs("ipapermright"),
		Type:        e.Str("type"),
		Attrs:       e.Strs("attrs"),
		BindType:    e.Str("ipapermbindruletype"),
		Location:    e.DN("ipapermlocation"),
		Filters:     e.Strs("ipapermtargetfilter"),
		TargetGroup: e.Str("targetgroup"),
		Privileges:  e.Strs("member_privilege"),
	}
}

// RoleShow fetches a role with `role_show`. Any authenticated user may read
// roles (System: Read Roles).
func (c *Client) RoleShow(name string) (*Role, error) {
	return c.RoleShowContext(context.Background(), name)
}

// RoleShowContext is like RoleShow but bounds the request with ctx.
func (c *Client) RoleShowContext(ctx context.Context, name string) (*Role, error) {
	if name == "" {
		return nil, errors.New("ipa: role name is required")
	}
	return showEntry(ctx, c, "role_show", []string{name}, roleFrom)
}

// RoleFind finds roles with `role_find`; options are passed through (e.g.
// `cn`, `description`, `sizelimit`). Any authenticated user may read roles
// (System: Read Roles).
func (c *Client) RoleFind(options Options) ([]*Role, error) {
	return c.RoleFindContext(context.Background(), options)
}

// RoleFindContext is like RoleFind but bounds the request with ctx.
func (c *Client) RoleFindContext(ctx context.Context, options Options) ([]*Role, error) {
	return findTyped(ctx, c, "role_find", []string{""}, options, roleFrom)
}

// PrivilegeShow fetches a privilege with `privilege_show`. Any authenticated
// user may read privileges (System: Read Privileges).
func (c *Client) PrivilegeShow(name string) (*Privilege, error) {
	return c.PrivilegeShowContext(context.Background(), name)
}

// PrivilegeShowContext is like PrivilegeShow but bounds the request with ctx.
func (c *Client) PrivilegeShowContext(ctx context.Context, name string) (*Privilege, error) {
	if name == "" {
		return nil, errors.New("ipa: privilege name is required")
	}
	return showEntry(ctx, c, "privilege_show", []string{name}, privilegeFrom)
}

// PrivilegeFind finds privileges with `privilege_find`; options are passed
// through (e.g. `cn`, `description`, `sizelimit`). Any authenticated user may
// read privileges (System: Read Privileges).
func (c *Client) PrivilegeFind(options Options) ([]*Privilege, error) {
	return c.PrivilegeFindContext(context.Background(), options)
}

// PrivilegeFindContext is like PrivilegeFind but bounds the request with ctx.
func (c *Client) PrivilegeFindContext(ctx context.Context, options Options) ([]*Privilege, error) {
	return findTyped(ctx, c, "privilege_find", []string{""}, options, privilegeFrom)
}

// PermissionShow fetches a permission with `permission_show`. Any
// authenticated user may read permissions (System: Read Permissions).
func (c *Client) PermissionShow(name string) (*Permission, error) {
	return c.PermissionShowContext(context.Background(), name)
}

// PermissionShowContext is like PermissionShow but bounds the request with ctx.
func (c *Client) PermissionShowContext(ctx context.Context, name string) (*Permission, error) {
	if name == "" {
		return nil, errors.New("ipa: permission name is required")
	}
	return showEntry(ctx, c, "permission_show", []string{name}, permissionFrom)
}

// PermissionFind finds permissions with `permission_find`; options are passed
// through (e.g. `cn`, `type`, `ipapermright`, `sizelimit`). Any authenticated
// user may read permissions (System: Read Permissions).
func (c *Client) PermissionFind(options Options) ([]*Permission, error) {
	return c.PermissionFindContext(context.Background(), options)
}

// PermissionFindContext is like PermissionFind but bounds the request with ctx.
func (c *Client) PermissionFindContext(ctx context.Context, options Options) ([]*Permission, error) {
	return findTyped(ctx, c, "permission_find", []string{""}, options, permissionFrom)
}
