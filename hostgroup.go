// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
)

// HostGroup is a FreeIPA host group. Attribute changes go through Modify
// ("hostgroup_mod").
type HostGroup struct {
	Name, Description string // cn, description
	// member_host, member_hostgroup, memberindirect_host, memberindirect_hostgroup
	Hosts, HostGroups, IndirectHosts, IndirectHostGroups []string
	MemberOf                                             []string // memberof_hostgroup
	ManagerUsers, ManagerGroups                          []string // membermanager_user, membermanager_group
}

func hostGroupFromEntry(e Entry) *HostGroup {
	return &HostGroup{
		Name:               e.Str("cn"),
		Description:        e.Str("description"),
		Hosts:              e.Strs("member_host"),
		HostGroups:         e.Strs("member_hostgroup"),
		IndirectHosts:      e.Strs("memberindirect_host"),
		IndirectHostGroups: e.Strs("memberindirect_hostgroup"),
		MemberOf:           e.Strs("memberof_hostgroup"),
		ManagerUsers:       e.Strs("membermanager_user"),
		ManagerGroups:      e.Strs("membermanager_group"),
	}
}

var errHostGroupName = errors.New("ipa: host group name is required")

// HostGroupShow fetches a host group with `hostgroup_show`. Any authenticated
// user may read host groups (System: Read Hostgroups).
func (c *Client) HostGroupShow(name string) (*HostGroup, error) {
	return c.HostGroupShowContext(context.Background(), name)
}

// HostGroupShowContext is like HostGroupShow but bounds the request with ctx.
func (c *Client) HostGroupShowContext(ctx context.Context, name string) (*HostGroup, error) {
	if name == "" {
		return nil, errHostGroupName
	}
	return showEntry(ctx, c, "hostgroup_show", []string{name}, hostGroupFromEntry)
}

// HostGroupFind finds host groups with `hostgroup_find`; options are passed
// through (e.g. `cn`, `host`, `in_hostgroup`, `sizelimit`). A truncated
// result comes back with ErrTruncated. Any authenticated user may read host
// groups (System: Read Hostgroups).
func (c *Client) HostGroupFind(options Options) ([]*HostGroup, error) {
	return c.HostGroupFindContext(context.Background(), options)
}

// HostGroupFindContext is like HostGroupFind but bounds the request with ctx.
func (c *Client) HostGroupFindContext(ctx context.Context, options Options) ([]*HostGroup, error) {
	return findTyped(ctx, c, "hostgroup_find", nil, options, hostGroupFromEntry)
}

// HostGroupAdd creates a host group with `hostgroup_add` from g's Name and
// Description and returns it; it requires the Host Group Administrators
// privilege (System: Add Hostgroups).
func (c *Client) HostGroupAdd(g *HostGroup) (*HostGroup, error) {
	return c.HostGroupAddContext(context.Background(), g)
}

// HostGroupAddContext is like HostGroupAdd but bounds the request with ctx.
func (c *Client) HostGroupAddContext(ctx context.Context, g *HostGroup) (*HostGroup, error) {
	if g == nil || g.Name == "" {
		return nil, errHostGroupName
	}
	o := Options{"all": true}
	if g.Description != "" {
		o["description"] = g.Description
	}
	e, _, err := Call[Entry](ctx, c, "hostgroup_add", []string{g.Name}, o)
	if err != nil {
		return nil, err
	}
	return hostGroupFromEntry(e), nil
}

// HostGroupDelete deletes host groups with `hostgroup_del`; it requires the
// Host Group Administrators privilege (System: Remove Hostgroups).
func (c *Client) HostGroupDelete(names ...string) error {
	return c.HostGroupDeleteContext(context.Background(), names...)
}

// HostGroupDeleteContext is like HostGroupDelete but bounds the request with ctx.
func (c *Client) HostGroupDeleteContext(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return errHostGroupName
	}
	_, err := c.rpc(ctx, "hostgroup_del", names, Options{"continue": false})
	return err
}

func (c *Client) hostGroupMembers(ctx context.Context, method, name string, lists map[string][]string) (*HostGroup, error) {
	if name == "" {
		return nil, errHostGroupName
	}
	e, err := c.memberEntry(ctx, method, []string{name}, lists)
	if err != nil && e.raw == nil {
		return nil, err
	}
	return hostGroupFromEntry(e), err
}

// HostGroupAddMember adds hosts and host groups to a host group with
// `hostgroup_add_member`. It needs the Host Group Administrators privilege
// (System: Modify Hostgroup Membership), or the caller is a member manager
// of the group; per-member problems are returned as *MemberError, together
// with the group as it stands.
func (c *Client) HostGroupAddMember(name string, hosts, hostgroups []string) (*HostGroup, error) {
	return c.HostGroupAddMemberContext(context.Background(), name, hosts, hostgroups)
}

// HostGroupAddMemberContext is like HostGroupAddMember but bounds the request with ctx.
func (c *Client) HostGroupAddMemberContext(ctx context.Context, name string, hosts, hostgroups []string) (*HostGroup, error) {
	return c.hostGroupMembers(ctx, "hostgroup_add_member", name, map[string][]string{"host": hosts, "hostgroup": hostgroups})
}

// HostGroupRemoveMember removes hosts and host groups from a host group with
// `hostgroup_remove_member`. It needs the Host Group Administrators privilege
// (System: Modify Hostgroup Membership), or the caller is a member manager
// of the group; per-member problems are returned as *MemberError, together
// with the group as it stands.
func (c *Client) HostGroupRemoveMember(name string, hosts, hostgroups []string) (*HostGroup, error) {
	return c.HostGroupRemoveMemberContext(context.Background(), name, hosts, hostgroups)
}

// HostGroupRemoveMemberContext is like HostGroupRemoveMember but bounds the request with ctx.
func (c *Client) HostGroupRemoveMemberContext(ctx context.Context, name string, hosts, hostgroups []string) (*HostGroup, error) {
	return c.hostGroupMembers(ctx, "hostgroup_remove_member", name, map[string][]string{"host": hosts, "hostgroup": hostgroups})
}

// HostGroupAddMemberManager makes users and groups member managers of a host
// group with `hostgroup_add_member_manager`; it requires the Host Group
// Administrators privilege (System: Modify Hostgroups). Per-member problems
// are returned as *MemberError, together with the group as it stands.
func (c *Client) HostGroupAddMemberManager(name string, users, groups []string) (*HostGroup, error) {
	return c.HostGroupAddMemberManagerContext(context.Background(), name, users, groups)
}

// HostGroupAddMemberManagerContext is like HostGroupAddMemberManager but bounds the request with ctx.
func (c *Client) HostGroupAddMemberManagerContext(ctx context.Context, name string, users, groups []string) (*HostGroup, error) {
	return c.hostGroupMembers(ctx, "hostgroup_add_member_manager", name, map[string][]string{"user": users, "group": groups})
}

// HostGroupRemoveMemberManager removes member managers from a host group with
// `hostgroup_remove_member_manager`; it requires the Host Group
// Administrators privilege (System: Modify Hostgroups). Per-member problems
// are returned as *MemberError, together with the group as it stands.
func (c *Client) HostGroupRemoveMemberManager(name string, users, groups []string) (*HostGroup, error) {
	return c.HostGroupRemoveMemberManagerContext(context.Background(), name, users, groups)
}

// HostGroupRemoveMemberManagerContext is like HostGroupRemoveMemberManager but bounds the request with ctx.
func (c *Client) HostGroupRemoveMemberManagerContext(ctx context.Context, name string, users, groups []string) (*HostGroup, error) {
	return c.hostGroupMembers(ctx, "hostgroup_remove_member_manager", name, map[string][]string{"user": users, "group": groups})
}
