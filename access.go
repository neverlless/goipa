// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"maps"

	"github.com/tidwall/gjson"
)

// HBACRule is a host-based access control rule. There is no HBACRuleMod:
// change other attributes with Modify("hbacrule_mod", name).
type HBACRule struct {
	// cn, description
	Name, Description string
	// ipaenabledflag
	Enabled bool
	// usercategory, hostcategory, servicecategory: "all" or ""
	UserCategory, HostCategory, ServiceCategory string
	// memberuser_user, memberuser_group
	Users, Groups []string
	// memberhost_host, memberhost_hostgroup
	Hosts, HostGroups []string
	// memberservice_hbacsvc, memberservice_hbacsvcgroup
	Services, ServiceGroups []string
}

// SudoRule is a sudo rule. Its description, order and categories change
// through Modify("sudorule_mod", name). FreeIPA keeps users, groups, hosts
// and run-as users and groups it does not know as external members
// (externaluser, externalhost, ipasudorunasextuser, ipasudorunasextusergroup,
// ipasudorunasextgroup), which SudoRule does not carry; adding such a name
// succeeds without a *MemberError.
type SudoRule struct {
	// cn, description
	Name, Description string
	// ipaenabledflag
	Enabled bool
	// usercategory, hostcategory, cmdcategory: "all" or ""
	UserCategory, HostCategory, CmdCategory string
	// ipasudorunasusercategory, ipasudorunasgroupcategory
	RunAsUserCategory, RunAsGroupCategory string
	// memberuser_user, memberuser_group, memberhost_host, memberhost_hostgroup
	Users, Groups, Hosts, HostGroups []string
	// memberallowcmd_sudocmd, memberallowcmd_sudocmdgroup,
	// memberdenycmd_sudocmd, memberdenycmd_sudocmdgroup
	AllowCommands, AllowCommandGroups, DenyCommands, DenyCommandGroups []string
	// ipasudorunas_user, ipasudorunasgroup_group
	RunAsUsers, RunAsGroups []string
	// ipasudorunas_group: groups whose members the commands may run as
	RunAsUserGroups []string
	// ipasudoopt
	Options []string
	// sudoorder
	Order int
}

// HBACRuleFind finds HBAC rules with `hbacrule_find`; options are passed
// through (e.g. `cn`, `ipaenabledflag`, `sizelimit`). Any authenticated user
// may read rules (System: Read HBAC Rules). FreeIPA returns at most its search
// limit (100 by default) unless `sizelimit` is set.
//
// A truncated search is not reported unless the Client was built
// WithTruncationErrors; FindEntries reports it too.
func (c *Client) HBACRuleFind(options Options) ([]*HBACRule, error) {
	return c.HBACRuleFindContext(context.Background(), options)
}

// HBACRuleFindContext is like HBACRuleFind but bounds the request with ctx.
func (c *Client) HBACRuleFindContext(ctx context.Context, options Options) ([]*HBACRule, error) {
	return findRules(ctx, c, "hbacrule_find", options, hbacRuleFrom)
}

// SudoRuleFind finds sudo rules with `sudorule_find`; options are passed
// through (e.g. `cn`, `ipaenabledflag`, `sizelimit`). Any authenticated user
// may read rules (System: Read Sudo Rules). FreeIPA returns at most its search
// limit (100 by default) unless `sizelimit` is set.
//
// A truncated search is not reported unless the Client was built
// WithTruncationErrors; FindEntries reports it too.
func (c *Client) SudoRuleFind(options Options) ([]*SudoRule, error) {
	return c.SudoRuleFindContext(context.Background(), options)
}

// SudoRuleFindContext is like SudoRuleFind but bounds the request with ctx.
func (c *Client) SudoRuleFindContext(ctx context.Context, options Options) ([]*SudoRule, error) {
	return findRules(ctx, c, "sudorule_find", options, parseSudoRule)
}

func parseSudoRule(r gjson.Result) *SudoRule {
	return &SudoRule{
		Name:               r.Get("cn.0").String(),
		Description:        r.Get("description.0").String(),
		Enabled:            boolAttr(r, "ipaenabledflag"),
		UserCategory:       r.Get("usercategory.0").String(),
		HostCategory:       r.Get("hostcategory.0").String(),
		CmdCategory:        r.Get("cmdcategory.0").String(),
		RunAsUserCategory:  r.Get("ipasudorunasusercategory.0").String(),
		RunAsGroupCategory: r.Get("ipasudorunasgroupcategory.0").String(),
		Users:              strList(r, "memberuser_user"),
		Groups:             strList(r, "memberuser_group"),
		Hosts:              strList(r, "memberhost_host"),
		HostGroups:         strList(r, "memberhost_hostgroup"),
		AllowCommands:      strList(r, "memberallowcmd_sudocmd"),
		AllowCommandGroups: strList(r, "memberallowcmd_sudocmdgroup"),
		DenyCommands:       strList(r, "memberdenycmd_sudocmd"),
		DenyCommandGroups:  strList(r, "memberdenycmd_sudocmdgroup"),
		RunAsUsers:         strList(r, "ipasudorunas_user"),
		RunAsUserGroups:    strList(r, "ipasudorunas_group"),
		RunAsGroups:        strList(r, "ipasudorunasgroup_group"),
		Options:            strList(r, "ipasudoopt"),
		Order:              int(r.Get("sudoorder.0").Int()),
	}
}

func findRules[T any](ctx context.Context, c *Client, method string, options Options, parse func(gjson.Result) *T) ([]*T, error) {
	options = maps.Clone(options)
	if options == nil {
		options = Options{}
	}
	options["no_members"] = false
	options["all"] = true

	res, err := c.rpc(ctx, method, []string{""}, options)
	if err != nil {
		return nil, err
	}
	out := make([]*T, 0)
	for _, r := range gjson.ParseBytes(res.Result.Data).Array() {
		out = append(out, parse(r))
	}
	return out, c.truncated(res)
}

// HBACTestResult is the outcome of HBACTest.
type HBACTestResult struct {
	// value
	Granted bool
	// matched, notmatched: names of the rules that did and did not match
	Matched, NotMatched []string
	// error, warning
	Errors, Warnings []string
}

// HBACTest runs `hbactest`. It evaluates HBAC rules on the server: every
// enabled rule, or only rules, disabled ones included. Any authenticated user
// may run it; it reads rules and group membership as the caller. FreeIPA
// ignores an unknown user, host or service instead of failing, so a typo
// reads as denied. If a name in rules does not exist, nothing is evaluated:
// Granted is false and Errors lists the unresolved names.
func (c *Client) HBACTest(user, host, service string, rules ...string) (*HBACTestResult, error) {
	return c.HBACTestContext(context.Background(), user, host, service, rules...)
}

// HBACTestContext is like HBACTest but bounds the request with ctx.
func (c *Client) HBACTestContext(ctx context.Context, user, host, service string, rules ...string) (*HBACTestResult, error) {
	if user == "" || host == "" || service == "" {
		return nil, errors.New("ipa: user, host and service are required")
	}
	// sizelimit 0 = unlimited; the default evaluates only the first 100 rules.
	options := Options{"user": user, "targethost": host, "service": service, "sizelimit": 0}
	if len(rules) > 0 {
		options["rules"] = rules
	}
	res, err := c.rpc(ctx, "hbactest", []string{}, options)
	if err != nil {
		return nil, err
	}
	// hbactest has no "result" key: value and the lists sit in the result object.
	r := gjson.ParseBytes(res.Result.Raw)
	return &HBACTestResult{
		Granted:    r.Get("value").Bool(),
		Matched:    strList(r, "matched"),
		NotMatched: strList(r, "notmatched"),
		Errors:     strList(r, "error"),
		Warnings:   strList(r, "warning"),
	}, nil
}
