// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
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
	var out []string
	res.Get(path).ForEach(func(_, v gjson.Result) bool {
		out = append(out, v.String())
		return true
	})
	return out
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
	if !group.NonPOSIX && group.GID != "" {
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
