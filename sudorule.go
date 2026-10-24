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

var errSudoRuleName = errors.New("ipa: sudo rule name is required")

func sudoRule(e Entry) *SudoRule { return parseSudoRule(gjson.ParseBytes(e.Raw())) }

// SudoRuleShow returns a sudo rule with `sudorule_show`.
// Any authenticated user may read rules (System: Read Sudo Rules).
func (c *Client) SudoRuleShow(name string) (*SudoRule, error) {
	return c.SudoRuleShowContext(context.Background(), name)
}

// SudoRuleShowContext is like SudoRuleShow but bounds the request with ctx.
func (c *Client) SudoRuleShowContext(ctx context.Context, name string) (*SudoRule, error) {
	if name == "" {
		return nil, errSudoRuleName
	}
	return showEntry(ctx, c, "sudorule_show", []string{name}, sudoRule)
}

// SudoRuleAdd creates a sudo rule with `sudorule_add` from r's name,
// description, the categories set to "all" and Order when positive (FreeIPA
// rejects an order another rule uses). New rules are enabled; r.Enabled is
// ignored. Members and options are added with the SudoRuleAdd* calls.
// It needs the Sudo Administrator privilege (System: Add Sudo rule).
func (c *Client) SudoRuleAdd(r *SudoRule) (*SudoRule, error) {
	return c.SudoRuleAddContext(context.Background(), r)
}

// SudoRuleAddContext is like SudoRuleAdd but bounds the request with ctx.
func (c *Client) SudoRuleAddContext(ctx context.Context, r *SudoRule) (*SudoRule, error) {
	if r == nil || r.Name == "" {
		return nil, errSudoRuleName
	}
	o := Options{"all": true}
	if r.Description != "" {
		o["description"] = r.Description
	}
	for k, v := range map[string]string{
		"usercategory": r.UserCategory, "hostcategory": r.HostCategory, "cmdcategory": r.CmdCategory,
		"ipasudorunasusercategory": r.RunAsUserCategory, "ipasudorunasgroupcategory": r.RunAsGroupCategory,
	} {
		if v == "all" {
			o[k] = v
		}
	}
	if r.Order > 0 {
		o["sudoorder"] = r.Order
	}
	e, _, err := Call[Entry](ctx, c, "sudorule_add", []string{r.Name}, o)
	if err != nil {
		return nil, err
	}
	return sudoRule(e), nil
}

// SudoRuleDelete deletes sudo rules with `sudorule_del`.
// It needs the Sudo Administrator privilege (System: Delete Sudo rule).
func (c *Client) SudoRuleDelete(names ...string) error {
	return c.SudoRuleDeleteContext(context.Background(), names...)
}

// SudoRuleDeleteContext is like SudoRuleDelete but bounds the request with ctx.
func (c *Client) SudoRuleDeleteContext(ctx context.Context, names ...string) error {
	if len(names) == 0 || slices.Contains(names, "") {
		return errSudoRuleName
	}
	_, err := c.rpc(ctx, "sudorule_del", names, Options{"continue": false})
	return err
}

// SudoRuleEnable enables a sudo rule with `sudorule_enable`. Enabling an
// enabled rule succeeds.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleEnable(name string) error {
	return c.SudoRuleEnableContext(context.Background(), name)
}

// SudoRuleEnableContext is like SudoRuleEnable but bounds the request with ctx.
func (c *Client) SudoRuleEnableContext(ctx context.Context, name string) error {
	return c.sudoRuleFlag(ctx, "sudorule_enable", name)
}

// SudoRuleDisable disables a sudo rule with `sudorule_disable`. Disabling a
// disabled rule succeeds.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleDisable(name string) error {
	return c.SudoRuleDisableContext(context.Background(), name)
}

// SudoRuleDisableContext is like SudoRuleDisable but bounds the request with ctx.
func (c *Client) SudoRuleDisableContext(ctx context.Context, name string) error {
	return c.sudoRuleFlag(ctx, "sudorule_disable", name)
}

func (c *Client) sudoRuleFlag(ctx context.Context, method, name string) error {
	if name == "" {
		return errSudoRuleName
	}
	_, err := c.rpc(ctx, method, []string{name}, nil)
	return err
}

func (c *Client) sudoMembers(ctx context.Context, method, name string, lists map[string][]string) (*SudoRule, error) {
	if name == "" {
		return nil, errSudoRuleName
	}
	return members(ctx, c, method, []string{name}, lists, sudoRule)
}

// sudoOptions sends one call per option, each a scalar: FreeIPA 4.9
// rejects any list for ipasudoopt with 3008 "Only one value is allowed" (Q83).
func (c *Client) sudoOptions(ctx context.Context, method, name string, options []string) (*SudoRule, error) {
	if name == "" {
		return nil, errSudoRuleName
	}
	if len(options) == 0 || slices.Contains(options, "") {
		return nil, errors.New("ipa: " + method + ": an option is required")
	}
	var e Entry
	for _, o := range options {
		var err error
		if e, _, err = Call[Entry](ctx, c, method, []string{name}, Options{"ipasudoopt": o, "all": true, "no_members": false}); err != nil {
			return nil, err
		}
	}
	return sudoRule(e), nil
}

// SudoRuleAddUser adds users and groups to a sudo rule with
// `sudorule_add_user`. Per-member problems are returned as *MemberError,
// together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddUser(name string, users, groups []string) (*SudoRule, error) {
	return c.SudoRuleAddUserContext(context.Background(), name, users, groups)
}

// SudoRuleAddUserContext is like SudoRuleAddUser but bounds the request with ctx.
func (c *Client) SudoRuleAddUserContext(ctx context.Context, name string, users, groups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_add_user", name, map[string][]string{"user": users, "group": groups})
}

// SudoRuleRemoveUser removes users and groups from a sudo rule with
// `sudorule_remove_user`. Per-member problems are returned as *MemberError,
// together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveUser(name string, users, groups []string) (*SudoRule, error) {
	return c.SudoRuleRemoveUserContext(context.Background(), name, users, groups)
}

// SudoRuleRemoveUserContext is like SudoRuleRemoveUser but bounds the request with ctx.
func (c *Client) SudoRuleRemoveUserContext(ctx context.Context, name string, users, groups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_remove_user", name, map[string][]string{"user": users, "group": groups})
}

// SudoRuleAddHost adds hosts and host groups to a sudo rule with
// `sudorule_add_host`. Per-member problems are returned as *MemberError,
// together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddHost(name string, hosts, hostgroups []string) (*SudoRule, error) {
	return c.SudoRuleAddHostContext(context.Background(), name, hosts, hostgroups)
}

// SudoRuleAddHostContext is like SudoRuleAddHost but bounds the request with ctx.
func (c *Client) SudoRuleAddHostContext(ctx context.Context, name string, hosts, hostgroups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_add_host", name, map[string][]string{"host": hosts, "hostgroup": hostgroups})
}

// SudoRuleRemoveHost removes hosts and host groups from a sudo rule with
// `sudorule_remove_host`. Per-member problems are returned as *MemberError,
// together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveHost(name string, hosts, hostgroups []string) (*SudoRule, error) {
	return c.SudoRuleRemoveHostContext(context.Background(), name, hosts, hostgroups)
}

// SudoRuleRemoveHostContext is like SudoRuleRemoveHost but bounds the request with ctx.
func (c *Client) SudoRuleRemoveHostContext(ctx context.Context, name string, hosts, hostgroups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_remove_host", name, map[string][]string{"host": hosts, "hostgroup": hostgroups})
}

// SudoRuleAddAllowCommand allows sudo commands and command groups in a sudo
// rule with `sudorule_add_allow_command`. Per-member problems are returned
// as *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddAllowCommand(name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.SudoRuleAddAllowCommandContext(context.Background(), name, cmds, cmdgroups)
}

// SudoRuleAddAllowCommandContext is like SudoRuleAddAllowCommand but bounds the request with ctx.
func (c *Client) SudoRuleAddAllowCommandContext(ctx context.Context, name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_add_allow_command", name, map[string][]string{"sudocmd": cmds, "sudocmdgroup": cmdgroups})
}

// SudoRuleRemoveAllowCommand removes allowed sudo commands and command groups
// from a sudo rule with `sudorule_remove_allow_command`. Per-member problems
// are returned as *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveAllowCommand(name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.SudoRuleRemoveAllowCommandContext(context.Background(), name, cmds, cmdgroups)
}

// SudoRuleRemoveAllowCommandContext is like SudoRuleRemoveAllowCommand but bounds the request with ctx.
func (c *Client) SudoRuleRemoveAllowCommandContext(ctx context.Context, name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_remove_allow_command", name, map[string][]string{"sudocmd": cmds, "sudocmdgroup": cmdgroups})
}

// SudoRuleAddDenyCommand denies sudo commands and command groups in a sudo
// rule with `sudorule_add_deny_command`. Per-member problems are returned as
// *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddDenyCommand(name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.SudoRuleAddDenyCommandContext(context.Background(), name, cmds, cmdgroups)
}

// SudoRuleAddDenyCommandContext is like SudoRuleAddDenyCommand but bounds the request with ctx.
func (c *Client) SudoRuleAddDenyCommandContext(ctx context.Context, name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_add_deny_command", name, map[string][]string{"sudocmd": cmds, "sudocmdgroup": cmdgroups})
}

// SudoRuleRemoveDenyCommand removes denied sudo commands and command groups
// from a sudo rule with `sudorule_remove_deny_command`. Per-member problems
// are returned as *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveDenyCommand(name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.SudoRuleRemoveDenyCommandContext(context.Background(), name, cmds, cmdgroups)
}

// SudoRuleRemoveDenyCommandContext is like SudoRuleRemoveDenyCommand but bounds the request with ctx.
func (c *Client) SudoRuleRemoveDenyCommandContext(ctx context.Context, name string, cmds, cmdgroups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_remove_deny_command", name, map[string][]string{"sudocmd": cmds, "sudocmdgroup": cmdgroups})
}

// SudoRuleAddRunAsUser lets a sudo rule run commands as users and as members
// of groups with `sudorule_add_runasuser`. Per-member problems are returned
// as *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddRunAsUser(name string, users, groups []string) (*SudoRule, error) {
	return c.SudoRuleAddRunAsUserContext(context.Background(), name, users, groups)
}

// SudoRuleAddRunAsUserContext is like SudoRuleAddRunAsUser but bounds the request with ctx.
func (c *Client) SudoRuleAddRunAsUserContext(ctx context.Context, name string, users, groups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_add_runasuser", name, map[string][]string{"user": users, "group": groups})
}

// SudoRuleRemoveRunAsUser removes run-as users and groups from a sudo rule
// with `sudorule_remove_runasuser`. Per-member problems are returned as
// *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveRunAsUser(name string, users, groups []string) (*SudoRule, error) {
	return c.SudoRuleRemoveRunAsUserContext(context.Background(), name, users, groups)
}

// SudoRuleRemoveRunAsUserContext is like SudoRuleRemoveRunAsUser but bounds the request with ctx.
func (c *Client) SudoRuleRemoveRunAsUserContext(ctx context.Context, name string, users, groups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_remove_runasuser", name, map[string][]string{"user": users, "group": groups})
}

// SudoRuleAddRunAsGroup lets a sudo rule run commands with the gid of groups
// with `sudorule_add_runasgroup`. Per-member problems are returned as
// *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddRunAsGroup(name string, groups []string) (*SudoRule, error) {
	return c.SudoRuleAddRunAsGroupContext(context.Background(), name, groups)
}

// SudoRuleAddRunAsGroupContext is like SudoRuleAddRunAsGroup but bounds the request with ctx.
func (c *Client) SudoRuleAddRunAsGroupContext(ctx context.Context, name string, groups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_add_runasgroup", name, map[string][]string{"group": groups})
}

// SudoRuleRemoveRunAsGroup removes run-as groups from a sudo rule with
// `sudorule_remove_runasgroup`. Per-member problems are returned as
// *MemberError, together with the rule as it stands.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveRunAsGroup(name string, groups []string) (*SudoRule, error) {
	return c.SudoRuleRemoveRunAsGroupContext(context.Background(), name, groups)
}

// SudoRuleRemoveRunAsGroupContext is like SudoRuleRemoveRunAsGroup but bounds the request with ctx.
func (c *Client) SudoRuleRemoveRunAsGroupContext(ctx context.Context, name string, groups []string) (*SudoRule, error) {
	return c.sudoMembers(ctx, "sudorule_remove_runasgroup", name, map[string][]string{"group": groups})
}

// SudoRuleAddOption adds sudoers options (ipasudoopt, e.g. "!authenticate")
// to a sudo rule with `sudorule_add_option`. An option the rule already has
// fails with FreeIPA's DuplicateEntry (4002). Each option is its own
// request, in order, as FreeIPA 4.9 takes one per call; the first failure
// stops the rest, leaving the earlier options added.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleAddOption(name string, options ...string) (*SudoRule, error) {
	return c.SudoRuleAddOptionContext(context.Background(), name, options...)
}

// SudoRuleAddOptionContext is like SudoRuleAddOption but bounds the request with ctx.
func (c *Client) SudoRuleAddOptionContext(ctx context.Context, name string, options ...string) (*SudoRule, error) {
	return c.sudoOptions(ctx, "sudorule_add_option", name, options)
}

// SudoRuleRemoveOption removes sudoers options from a sudo rule with
// `sudorule_remove_option`. An option the rule does not have fails the call
// with FreeIPA's AttrValueNotFound (4026). Each option is its own request,
// in order, as FreeIPA 4.9 takes one per call; the first failure stops the
// rest, leaving the earlier options removed.
// It needs the Sudo Administrator privilege (System: Modify Sudo rule).
func (c *Client) SudoRuleRemoveOption(name string, options ...string) (*SudoRule, error) {
	return c.SudoRuleRemoveOptionContext(context.Background(), name, options...)
}

// SudoRuleRemoveOptionContext is like SudoRuleRemoveOption but bounds the request with ctx.
func (c *Client) SudoRuleRemoveOptionContext(ctx context.Context, name string, options ...string) (*SudoRule, error) {
	return c.sudoOptions(ctx, "sudorule_remove_option", name, options)
}
