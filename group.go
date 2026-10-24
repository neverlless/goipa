// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/tidwall/gjson"
)

// Group is a FreeIPA user group.
type Group struct {
	Name, Description, GID string
	// member_user, member_group, memberindirect_user, memberindirect_group
	Users, Groups, IndirectUsers, IndirectGroups []string
	// memberof_group
	MemberOf []string
	// membermanager_user, membermanager_group
	ManagerUsers, ManagerGroups []string
	// External: objectclass has ipaexternalgroup. NonPOSIX: objectclass lacks
	// posixgroup. The zero value is a POSIX group.
	External, NonPOSIX bool
}

func strList(res gjson.Result, path string) []string {
	v := res.Get(path)
	if v.Type == gjson.Null {
		return nil
	}
	var out []string
	v.ForEach(func(_, v gjson.Result) bool {
		out = append(out, v.String())
		return true
	})
	return out
}

// boolAttr reads a boolean FreeIPA attribute: true, [true], "TRUE" or
// ["TRUE"], case-insensitive.
func boolAttr(res gjson.Result, key string) bool {
	v := res.Get(key)
	if v.IsArray() {
		v = v.Get("0")
	}
	return v.Bool() || strings.EqualFold(v.String(), "true")
}

func (g *Group) fromJSON(raw []byte) error {
	if !gjson.ValidBytes(raw) {
		return errors.New("invalid group record json")
	}
	res := gjson.ParseBytes(raw)

	g.Name = res.Get("cn.0").String()
	g.Description = res.Get("description.0").String()
	g.GID = res.Get("gidnumber.0").String()
	g.Users = strList(res, "member_user")
	g.Groups = strList(res, "member_group")
	g.IndirectUsers = strList(res, "memberindirect_user")
	g.IndirectGroups = strList(res, "memberindirect_group")
	g.MemberOf = strList(res, "memberof_group")
	g.ManagerUsers = strList(res, "membermanager_user")
	g.ManagerGroups = strList(res, "membermanager_group")
	g.External, g.NonPOSIX = false, true
	for _, oc := range strList(res, "objectclass") {
		switch {
		case strings.EqualFold(oc, "ipaexternalgroup"):
			g.External = true
		case strings.EqualFold(oc, "posixgroup"):
			g.NonPOSIX = false
		}
	}
	return nil
}

// GroupShow fetches a group with `group_show`. Any authenticated user may read
// groups (System: Read Groups).
func (c *Client) GroupShow(name string) (*Group, error) {
	return c.GroupShowContext(context.Background(), name)
}

// GroupShowContext is like GroupShow but bounds the request with ctx.
func (c *Client) GroupShowContext(ctx context.Context, name string) (*Group, error) {
	if name == "" {
		return nil, errors.New("ipa: group name is required")
	}
	res, err := c.rpc(ctx, "group_show", []string{name}, Options{"no_members": false, "all": true})
	if err != nil {
		return nil, err
	}
	g := new(Group)
	if err := g.fromJSON(res.Result.Data); err != nil {
		return nil, err
	}
	return g, nil
}

// GroupFind finds groups with `group_find`; options are passed through (e.g.
// `cn`, `user`, `in_group`, `sizelimit`). Any authenticated user may read
// groups (System: Read Groups).
//
// A truncated search is not reported (kept for compatibility); use FindEntries
// with the same method to detect it.
func (c *Client) GroupFind(options Options) ([]*Group, error) {
	return c.GroupFindContext(context.Background(), options)
}

// GroupFindContext is like GroupFind but bounds the request with ctx.
func (c *Client) GroupFindContext(ctx context.Context, options Options) ([]*Group, error) {
	options = maps.Clone(options)
	if options == nil {
		options = Options{}
	}
	options["no_members"] = false
	options["all"] = true

	res, err := c.rpc(ctx, "group_find", []string{""}, options)
	if err != nil {
		return nil, err
	}
	groups := make([]*Group, 0)
	for _, t := range gjson.ParseBytes(res.Result.Data).Array() {
		g := new(Group)
		if err := g.fromJSON([]byte(t.Raw)); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

func groupResult(res *Response) (*Group, error) {
	g := new(Group)
	if err := g.fromJSON(res.Result.Data); err != nil {
		return nil, err
	}
	return g, nil
}

// GroupAdd creates a group with `group_add` and returns it; it requires the
// Group Administrators privilege (System: Add Groups). A zero Group creates a
// POSIX group, as `ipa group-add` does; set NonPOSIX for a group without a
// GID.
func (c *Client) GroupAdd(group *Group) (*Group, error) {
	return c.GroupAddContext(context.Background(), group)
}

// GroupAddContext is like GroupAdd but bounds the request with ctx.
func (c *Client) GroupAddContext(ctx context.Context, group *Group) (*Group, error) {
	if group == nil || group.Name == "" {
		return nil, errors.New("ipa: group name is required")
	}
	options := Options{"all": true}
	if group.Description != "" {
		options["description"] = group.Description
	}
	if !group.NonPOSIX && !group.External && group.GID != "" {
		options["gidnumber"] = group.GID
	}
	if group.External {
		options["external"] = true
	} else if group.NonPOSIX {
		options["nonposix"] = true
	}
	res, err := c.rpc(ctx, "group_add", []string{group.Name}, options)
	if err != nil {
		return nil, err
	}
	return groupResult(res)
}

// GroupMod changes a group's description (an empty one clears it) and, for a
// POSIX group, its GID with `group_mod`; it requires the Group Administrators
// privilege (System: Modify Groups). It returns group itself when nothing
// changed. Conversion between group types and renames go through RPC.
func (c *Client) GroupMod(group *Group) (*Group, error) {
	return c.GroupModContext(context.Background(), group)
}

// GroupModContext is like GroupMod but bounds the request with ctx.
func (c *Client) GroupModContext(ctx context.Context, group *Group) (*Group, error) {
	if group == nil || group.Name == "" {
		return nil, errors.New("ipa: group name is required")
	}
	options := Options{"all": true, "description": group.Description}
	if !group.NonPOSIX && group.GID != "" {
		options["gidnumber"] = group.GID
	}
	res, err := c.rpc(ctx, "group_mod", []string{group.Name}, options)
	if err != nil {
		if errors.Is(err, ErrEmptyModlist) {
			return group, nil
		}
		return nil, err
	}
	return groupResult(res)
}

// GroupDelete deletes groups with `group_del`; it requires the Group
// Administrators privilege (System: Remove Groups).
func (c *Client) GroupDelete(names ...string) error {
	return c.GroupDeleteContext(context.Background(), names...)
}

// GroupDeleteContext is like GroupDelete but bounds the request with ctx.
func (c *Client) GroupDeleteContext(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return errors.New("ipa: group name is required")
	}
	_, err := c.rpc(ctx, "group_del", names, Options{"continue": false})
	return err
}

// MemberFailure is one member FreeIPA refused to add or remove.
type MemberFailure struct {
	Kind    string // "member", "membermanager" or "condition" (automember)
	Type    string // the key FreeIPA reports: "user", "group", "host", "hbacsvc", ..., or the automember regex attribute
	Name    string
	Message string
}

// MemberError reports the members a member call could not change.
// FreeIPA lists them in the result, with no error, even when the caller lacks
// the right to change members at all.
type MemberError struct {
	Failures []MemberFailure
}

func (e *MemberError) Error() string {
	parts := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		parts[i] = fmt.Sprintf("%s %s: %s", f.Type, f.Name, f.Message)
	}
	s := "s"
	if len(parts) == 1 {
		s = ""
	}
	return fmt.Sprintf("ipa: %d member failure%s: %s", len(parts), s, strings.Join(parts, "; "))
}

func parseMemberFailures(failed json.RawMessage) []MemberFailure {
	var out []MemberFailure
	gjson.ParseBytes(failed).ForEach(func(kind, types gjson.Result) bool {
		types.ForEach(func(typ, pairs gjson.Result) bool {
			for _, p := range pairs.Array() {
				out = append(out, MemberFailure{Kind: kind.String(), Type: typ.String(), Name: p.Get("0").String(), Message: p.Get("1").String()})
			}
			return true
		})
		return true
	})
	return out
}

// groupMembers has the same contract as members.
func (c *Client) groupMembers(ctx context.Context, method, group string, users, groups []string) (*Group, error) {
	if group == "" {
		return nil, errors.New("ipa: group name is required")
	}
	if len(users) == 0 && len(groups) == 0 {
		return nil, errors.New("ipa: no users or groups given")
	}
	options := Options{"all": true}
	if len(users) > 0 {
		options["user"] = users
	}
	if len(groups) > 0 {
		options["group"] = groups
	}
	res, err := c.rpc(ctx, method, []string{group}, options)
	if err != nil {
		return nil, err
	}
	g, err := groupResult(res)
	if err != nil {
		return nil, err
	}
	// Failed may be absent or the bytes null; both parse to no failures.
	if f := parseMemberFailures(res.Result.Failed); len(f) > 0 {
		return g, &MemberError{Failures: f}
	}
	return g, nil
}

// GroupAddMember adds users and groups to a group with `group_add_member`. It
// needs the Group Administrators or Modify Group membership privilege, or the
// caller is a member manager of the group; per-member problems, including
// insufficient access, are returned as *MemberError, together with the group
// as it stands. This is the context-aware API from ubccr/goipa#17, generalised
// to users and groups.
func (c *Client) GroupAddMember(group string, users, groups []string) (*Group, error) {
	return c.GroupAddMemberContext(context.Background(), group, users, groups)
}

// GroupAddMemberContext is like GroupAddMember but bounds the request with ctx.
func (c *Client) GroupAddMemberContext(ctx context.Context, group string, users, groups []string) (*Group, error) {
	return c.groupMembers(ctx, "group_add_member", group, users, groups)
}

// GroupRemoveMember removes users and groups from a group with
// `group_remove_member`. It needs the Group Administrators or Modify Group
// membership privilege, or the caller is a member manager of the group;
// per-member problems, including insufficient access, are returned as
// *MemberError, together with the group as it stands.
func (c *Client) GroupRemoveMember(group string, users, groups []string) (*Group, error) {
	return c.GroupRemoveMemberContext(context.Background(), group, users, groups)
}

// GroupRemoveMemberContext is like GroupRemoveMember but bounds the request with ctx.
func (c *Client) GroupRemoveMemberContext(ctx context.Context, group string, users, groups []string) (*Group, error) {
	return c.groupMembers(ctx, "group_remove_member", group, users, groups)
}

// GroupAddMemberManager makes users and groups member managers of a group
// with `group_add_member_manager`; it requires the Group Administrators
// privilege (System: Modify Groups). Per-member problems are returned as
// *MemberError, together with the group as it stands.
func (c *Client) GroupAddMemberManager(group string, users, groups []string) (*Group, error) {
	return c.GroupAddMemberManagerContext(context.Background(), group, users, groups)
}

// GroupAddMemberManagerContext is like GroupAddMemberManager but bounds the request with ctx.
func (c *Client) GroupAddMemberManagerContext(ctx context.Context, group string, users, groups []string) (*Group, error) {
	return c.groupMembers(ctx, "group_add_member_manager", group, users, groups)
}

// GroupRemoveMemberManager removes member managers from a group with
// `group_remove_member_manager`; it requires the Group Administrators
// privilege (System: Modify Groups). Per-member problems are returned as
// *MemberError, together with the group as it stands.
func (c *Client) GroupRemoveMemberManager(group string, users, groups []string) (*Group, error) {
	return c.GroupRemoveMemberManagerContext(context.Background(), group, users, groups)
}

// GroupRemoveMemberManagerContext is like GroupRemoveMemberManager but bounds the request with ctx.
func (c *Client) GroupRemoveMemberManagerContext(ctx context.Context, group string, users, groups []string) (*Group, error) {
	return c.groupMembers(ctx, "group_remove_member_manager", group, users, groups)
}
