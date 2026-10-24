// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"slices"

	"github.com/tidwall/gjson"
)

var errHBACRuleName = errors.New("ipa: HBAC rule name is required")

func hbacRuleFrom(r gjson.Result) *HBACRule {
	return &HBACRule{
		Name:            r.Get("cn.0").String(),
		Description:     r.Get("description.0").String(),
		Enabled:         boolAttr(r, "ipaenabledflag"),
		UserCategory:    r.Get("usercategory.0").String(),
		HostCategory:    r.Get("hostcategory.0").String(),
		ServiceCategory: r.Get("servicecategory.0").String(),
		Users:           strList(r, "memberuser_user"),
		Groups:          strList(r, "memberuser_group"),
		Hosts:           strList(r, "memberhost_host"),
		HostGroups:      strList(r, "memberhost_hostgroup"),
		Services:        strList(r, "memberservice_hbacsvc"),
		ServiceGroups:   strList(r, "memberservice_hbacsvcgroup"),
	}
}

func hbacRuleEntry(e Entry) *HBACRule { return hbacRuleFrom(gjson.ParseBytes(e.Raw())) }

// HBACRuleShow fetches an HBAC rule with `hbacrule_show`. Any authenticated
// user may read rules (System: Read HBAC Rules). Attributes the typed calls
// do not cover change through Modify("hbacrule_mod", name).
func (c *Client) HBACRuleShow(name string) (*HBACRule, error) {
	return c.HBACRuleShowContext(context.Background(), name)
}

// HBACRuleShowContext is like HBACRuleShow but bounds the request with ctx.
func (c *Client) HBACRuleShowContext(ctx context.Context, name string) (*HBACRule, error) {
	if name == "" {
		return nil, errHBACRuleName
	}
	return showEntry(ctx, c, "hbacrule_show", []string{name}, hbacRuleEntry)
}

// HBACRuleAdd creates an HBAC rule with `hbacrule_add`; it requires the HBAC
// Administrator privilege (System: Add HBAC Rule). It sends the name, the
// description and the categories set to "all"; members are added with the
// HBACRuleAdd* calls. Enabled is ignored: new rules are enabled.
func (c *Client) HBACRuleAdd(r *HBACRule) (*HBACRule, error) {
	return c.HBACRuleAddContext(context.Background(), r)
}

// HBACRuleAddContext is like HBACRuleAdd but bounds the request with ctx.
func (c *Client) HBACRuleAddContext(ctx context.Context, r *HBACRule) (*HBACRule, error) {
	if r == nil || r.Name == "" {
		return nil, errHBACRuleName
	}
	o := Options{"all": true}
	if r.Description != "" {
		o["description"] = r.Description
	}
	for k, v := range map[string]string{"usercategory": r.UserCategory, "hostcategory": r.HostCategory, "servicecategory": r.ServiceCategory} {
		if v == "all" {
			o[k] = v
		}
	}
	e, _, err := Call[Entry](ctx, c, "hbacrule_add", []string{r.Name}, o)
	if err != nil {
		return nil, err
	}
	return hbacRuleEntry(e), nil
}

// HBACRuleDelete deletes HBAC rules with `hbacrule_del` in one call; it
// requires the HBAC Administrator privilege (System: Delete HBAC Rule).
func (c *Client) HBACRuleDelete(names ...string) error {
	return c.HBACRuleDeleteContext(context.Background(), names...)
}

// HBACRuleDeleteContext is like HBACRuleDelete but bounds the request with ctx.
func (c *Client) HBACRuleDeleteContext(ctx context.Context, names ...string) error {
	if len(names) == 0 || slices.Contains(names, "") {
		return errHBACRuleName
	}
	_, err := c.rpc(ctx, "hbacrule_del", names, Options{"continue": false})
	return err
}

// HBACRuleEnable enables an HBAC rule with `hbacrule_enable`; it requires the
// HBAC Administrator privilege (System: Modify HBAC Rule). Enabling an
// enabled rule succeeds.
func (c *Client) HBACRuleEnable(name string) error {
	return c.HBACRuleEnableContext(context.Background(), name)
}

// HBACRuleEnableContext is like HBACRuleEnable but bounds the request with ctx.
func (c *Client) HBACRuleEnableContext(ctx context.Context, name string) error {
	return c.hbacRuleToggle(ctx, "hbacrule_enable", name)
}

// HBACRuleDisable disables an HBAC rule with `hbacrule_disable`; it requires
// the HBAC Administrator privilege (System: Modify HBAC Rule). Disabling a
// disabled rule succeeds.
func (c *Client) HBACRuleDisable(name string) error {
	return c.HBACRuleDisableContext(context.Background(), name)
}

// HBACRuleDisableContext is like HBACRuleDisable but bounds the request with ctx.
func (c *Client) HBACRuleDisableContext(ctx context.Context, name string) error {
	return c.hbacRuleToggle(ctx, "hbacrule_disable", name)
}

func (c *Client) hbacRuleToggle(ctx context.Context, method, name string) error {
	if name == "" {
		return errHBACRuleName
	}
	_, err := c.rpc(ctx, method, []string{name}, Options{})
	return err
}

// HBACRuleAddUser adds users and groups to an HBAC rule with
// `hbacrule_add_user`; it requires the HBAC Administrator privilege (System:
// Manage HBAC Rule Membership). A rule with user category "all" is 4303
// MutuallyExclusiveError. Per-member problems are returned as *MemberError,
// together with the rule as it stands.
func (c *Client) HBACRuleAddUser(name string, users, groups []string) (*HBACRule, error) {
	return c.HBACRuleAddUserContext(context.Background(), name, users, groups)
}

// HBACRuleAddUserContext is like HBACRuleAddUser but bounds the request with ctx.
func (c *Client) HBACRuleAddUserContext(ctx context.Context, name string, users, groups []string) (*HBACRule, error) {
	return c.hbacRuleMembers(ctx, "hbacrule_add_user", name, map[string][]string{"user": users, "group": groups})
}

// HBACRuleRemoveUser removes users and groups from an HBAC rule with
// `hbacrule_remove_user`; it requires the HBAC Administrator privilege
// (System: Manage HBAC Rule Membership). Per-member problems are returned as
// *MemberError, together with the rule as it stands.
func (c *Client) HBACRuleRemoveUser(name string, users, groups []string) (*HBACRule, error) {
	return c.HBACRuleRemoveUserContext(context.Background(), name, users, groups)
}

// HBACRuleRemoveUserContext is like HBACRuleRemoveUser but bounds the request with ctx.
func (c *Client) HBACRuleRemoveUserContext(ctx context.Context, name string, users, groups []string) (*HBACRule, error) {
	return c.hbacRuleMembers(ctx, "hbacrule_remove_user", name, map[string][]string{"user": users, "group": groups})
}

// HBACRuleAddHost adds hosts and host groups to an HBAC rule with
// `hbacrule_add_host`; it requires the HBAC Administrator privilege (System:
// Manage HBAC Rule Membership). A rule with host category "all" is 4303
// MutuallyExclusiveError. Per-member problems are returned as *MemberError,
// together with the rule as it stands.
func (c *Client) HBACRuleAddHost(name string, hosts, hostgroups []string) (*HBACRule, error) {
	return c.HBACRuleAddHostContext(context.Background(), name, hosts, hostgroups)
}

// HBACRuleAddHostContext is like HBACRuleAddHost but bounds the request with ctx.
func (c *Client) HBACRuleAddHostContext(ctx context.Context, name string, hosts, hostgroups []string) (*HBACRule, error) {
	return c.hbacRuleMembers(ctx, "hbacrule_add_host", name, map[string][]string{"host": hosts, "hostgroup": hostgroups})
}

// HBACRuleRemoveHost removes hosts and host groups from an HBAC rule with
// `hbacrule_remove_host`; it requires the HBAC Administrator privilege
// (System: Manage HBAC Rule Membership). Per-member problems are returned as
// *MemberError, together with the rule as it stands.
func (c *Client) HBACRuleRemoveHost(name string, hosts, hostgroups []string) (*HBACRule, error) {
	return c.HBACRuleRemoveHostContext(context.Background(), name, hosts, hostgroups)
}

// HBACRuleRemoveHostContext is like HBACRuleRemoveHost but bounds the request with ctx.
func (c *Client) HBACRuleRemoveHostContext(ctx context.Context, name string, hosts, hostgroups []string) (*HBACRule, error) {
	return c.hbacRuleMembers(ctx, "hbacrule_remove_host", name, map[string][]string{"host": hosts, "hostgroup": hostgroups})
}

// HBACRuleAddService adds HBAC services (hbacsvc) and service groups
// (hbacsvcgroup) to an HBAC rule with `hbacrule_add_service`; it requires the
// HBAC Administrator privilege (System: Manage HBAC Rule Membership). A rule
// with service category "all" is 4303 MutuallyExclusiveError. Per-member
// problems are returned as *MemberError, together with the rule as it stands.
func (c *Client) HBACRuleAddService(name string, services, servicegroups []string) (*HBACRule, error) {
	return c.HBACRuleAddServiceContext(context.Background(), name, services, servicegroups)
}

// HBACRuleAddServiceContext is like HBACRuleAddService but bounds the request with ctx.
func (c *Client) HBACRuleAddServiceContext(ctx context.Context, name string, services, servicegroups []string) (*HBACRule, error) {
	return c.hbacRuleMembers(ctx, "hbacrule_add_service", name, map[string][]string{"hbacsvc": services, "hbacsvcgroup": servicegroups})
}

// HBACRuleRemoveService removes HBAC services and service groups from an HBAC
// rule with `hbacrule_remove_service`; it requires the HBAC Administrator
// privilege (System: Manage HBAC Rule Membership). Per-member problems are
// returned as *MemberError, together with the rule as it stands.
func (c *Client) HBACRuleRemoveService(name string, services, servicegroups []string) (*HBACRule, error) {
	return c.HBACRuleRemoveServiceContext(context.Background(), name, services, servicegroups)
}

// HBACRuleRemoveServiceContext is like HBACRuleRemoveService but bounds the request with ctx.
func (c *Client) HBACRuleRemoveServiceContext(ctx context.Context, name string, services, servicegroups []string) (*HBACRule, error) {
	return c.hbacRuleMembers(ctx, "hbacrule_remove_service", name, map[string][]string{"hbacsvc": services, "hbacsvcgroup": servicegroups})
}

func (c *Client) hbacRuleMembers(ctx context.Context, method, name string, lists map[string][]string) (*HBACRule, error) {
	if name == "" {
		return nil, errHBACRuleName
	}
	return members(ctx, c, method, []string{name}, lists, hbacRuleEntry)
}
