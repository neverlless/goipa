// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	ipa "github.com/neverlless/goipa"
)

// HBACRule is an HBAC rule of the fake server.
type HBACRule struct {
	Description string
	Disabled    bool // zero = enabled, FreeIPA's default
	// UserCategory, HostCategory and ServiceCategory are "all" or "".
	UserCategory, HostCategory, ServiceCategory string
	// Users and Groups are memberuser_*, Hosts and HostGroups memberhost_*,
	// Services and ServiceGroups memberservice_hbacsvc[group].
	Users, Groups, Hosts, HostGroups, Services, ServiceGroups []string
}

// SudoRule is a sudo rule of the fake server.
type SudoRule struct {
	Description string
	Disabled    bool // zero = enabled, FreeIPA's default
	// The categories are "all" or "".
	UserCategory, HostCategory, CmdCategory, RunAsUserCategory, RunAsGroupCategory string
	Users, Groups, Hosts, HostGroups                                               []string
	AllowCommands, AllowCommandGroups, DenyCommands, DenyCommandGroups             []string
	RunAsUsers, RunAsGroups                                                        []string
	Options                                                                        []string // ipasudoopt
	Order                                                                          int      // sudoorder, 0 = unset
}

type hbacRec struct {
	HBACRule
	uuid string
}

type sudoRec struct {
	SudoRule
	uuid string
}

func (r HBACRule) clone() HBACRule {
	for _, p := range []*[]string{&r.Users, &r.Groups, &r.Hosts, &r.HostGroups, &r.Services, &r.ServiceGroups} {
		*p = cloneStrs(*p)
	}
	return r
}

func (r SudoRule) clone() SudoRule {
	for _, p := range []*[]string{&r.Users, &r.Groups, &r.Hosts, &r.HostGroups, &r.AllowCommands, &r.AllowCommandGroups,
		&r.DenyCommands, &r.DenyCommandGroups, &r.RunAsUsers, &r.RunAsGroups, &r.Options} {
		*p = cloneStrs(*p)
	}
	return r
}

// AddHBACRule creates or replaces HBAC rule cn. New servers already hold
// allow_all, as every FreeIPA does.
func (s *Server) AddHBACRule(cn string, r HBACRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hbac[cn] = &hbacRec{HBACRule: r.clone(), uuid: newUUID()}
}

// dropFromRules removes a deleted user (or group) from every rule's users
// (or groups).
func (s *Server) dropFromRules(name string, group bool) {
	is := func(n string) bool { return n == name }
	for _, r := range s.hbac {
		r.Users, r.Groups = drop(r.Users, r.Groups, group, is)
	}
	for _, r := range s.sudo {
		r.Users, r.Groups = drop(r.Users, r.Groups, group, is)
	}
}

func drop(users, groups []string, group bool, is func(string) bool) ([]string, []string) {
	if group {
		return users, slices.DeleteFunc(groups, is)
	}
	return slices.DeleteFunc(users, is), groups
}

// AddSudoRule creates or replaces sudo rule cn.
func (s *Server) AddSudoRule(cn string, r SudoRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sudo[cn] = &sudoRec{SudoRule: r.clone(), uuid: newUUID()}
}

func seedAllowAll() map[string]*hbacRec {
	return map[string]*hbacRec{"allow_all": {
		HBACRule: HBACRule{
			Description:  "Allow all users to access any host from any host",
			UserCategory: "all", HostCategory: "all", ServiceCategory: "all",
		},
		uuid: newUUID(),
	}}
}

// ruleOut fills the attributes both rule kinds share.
func ruleOut(cn, desc string, disabled bool, cats map[string]string, members map[string][]string, showMembers, all bool, dn string, oc ...string) map[string]any {
	out := map[string]any{"cn": []string{cn}, "ipaenabledflag": []string{"TRUE"}}
	if disabled {
		out["ipaenabledflag"] = []string{"FALSE"}
	}
	if desc != "" {
		out["description"] = []string{desc}
	}
	for k, v := range cats {
		if v != "" {
			out[k] = []string{v}
		}
	}
	if showMembers {
		for k, v := range members {
			if len(v) > 0 {
				out[k] = slices.Clone(v) // writeEnvelope marshals after s.mu is released
			}
		}
	}
	if all {
		out["objectclass"] = oc
		out["dn"] = dn
	}
	return out
}

func (r *hbacRec) render(cn string, members, all bool) map[string]any {
	return ruleOut(cn, r.Description, r.Disabled,
		map[string]string{"usercategory": r.UserCategory, "hostcategory": r.HostCategory, "servicecategory": r.ServiceCategory},
		map[string][]string{
			"memberuser_user": r.Users, "memberuser_group": r.Groups,
			"memberhost_host": r.Hosts, "memberhost_hostgroup": r.HostGroups,
			"memberservice_hbacsvc": r.Services, "memberservice_hbacsvcgroup": r.ServiceGroups,
		}, members, all, "ipaUniqueID="+r.uuid+",cn=hbac,dc=test,dc=local", "ipaassociation", "ipahbacrule")
}

func (r *sudoRec) render(cn string, members, all bool) map[string]any {
	out := ruleOut(cn, r.Description, r.Disabled,
		map[string]string{"usercategory": r.UserCategory, "hostcategory": r.HostCategory, "cmdcategory": r.CmdCategory,
			"ipasudorunasusercategory": r.RunAsUserCategory, "ipasudorunasgroupcategory": r.RunAsGroupCategory},
		map[string][]string{
			"memberuser_user": r.Users, "memberuser_group": r.Groups,
			"memberhost_host": r.Hosts, "memberhost_hostgroup": r.HostGroups,
			"memberallowcmd_sudocmd": r.AllowCommands, "memberallowcmd_sudocmdgroup": r.AllowCommandGroups,
			"memberdenycmd_sudocmd": r.DenyCommands, "memberdenycmd_sudocmdgroup": r.DenyCommandGroups,
			"ipasudorunas_user": r.RunAsUsers, "ipasudorunasgroup_group": r.RunAsGroups,
		}, members, all, "ipaUniqueID="+r.uuid+",cn=sudorules,cn=sudo,dc=test,dc=local", "ipaassociation", "ipasudorule")
	if len(r.Options) > 0 {
		out["ipasudoopt"] = slices.Clone(r.Options)
	}
	if r.Order > 0 {
		out["sudoorder"] = []string{strconv.Itoa(r.Order)}
	}
	return out
}

// ruleFind serves hbacrule_find and sudorule_find (Q34).
func ruleFind[T any](c Call, rules map[string]*T, desc func(*T) string, disabled func(*T) bool, render func(*T, string, bool, bool) map[string]any) (any, *ipa.IpaError) {
	needle := ""
	if len(c.Args) > 0 {
		needle = strings.ToLower(c.Args[0])
	}
	all := flag(c, "all")
	members := all
	if v, ok := c.Options["no_members"].(bool); ok && !v { // U1
		members = true
	}
	var cns []string
	for cn, r := range rules {
		if needle != "" && !strings.Contains(strings.ToLower(cn), needle) && !strings.Contains(strings.ToLower(desc(r)), needle) {
			continue
		}
		if !matches(c, "cn", cn) || !matches(c, "description", desc(r)) {
			continue
		}
		if v, ok := c.Options["ipaenabledflag"]; ok && strings.EqualFold(fmt.Sprint(v), "true") == disabled(r) {
			continue
		}
		cns = append(cns, cn)
	}
	sort.Strings(cns)
	recs := make([]map[string]any, 0, len(cns))
	for _, cn := range cns {
		recs = append(recs, render(rules[cn], cn, members, all))
	}
	return list(recs), nil
}

func ruleName(c Call) (string, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", required("cn")
	}
	return c.Args[0], nil
}

func ruleAdd[T any](kind string, rules map[string]*T, c Call, mk func(Call) *T, render func(*T, string, bool, bool) map[string]any) (any, *ipa.IpaError) {
	cn, err := ruleName(c)
	if err != nil {
		return nil, err
	}
	if rules[cn] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: kind + ` with name "` + cn + `" already exists`}
	}
	r := mk(c)
	rules[cn] = r
	return entry(cn, render(r, cn, false, flag(c, "all")), fmt.Sprintf("Added %s %q", kind, cn)), nil
}

func ruleDel[T any](kind string, rules map[string]*T, c Call) (any, *ipa.IpaError) {
	for _, cn := range c.Args {
		if rules[cn] == nil {
			return nil, notFound(cn, kind)
		}
	}
	deleted := slices.Clone(c.Args)
	for _, cn := range deleted {
		delete(rules, cn)
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   deleted,
		"summary": fmt.Sprintf("Deleted %s %q", kind, strings.Join(deleted, ",")),
	}, nil
}

// ruleAddUser is hbacrule_add_user and sudorule_add_user: user and group
// options, group_add_member's output with failed.memberuser.{user,group}.
func ruleAddUser[T any](s *Server, rules map[string]*T, kind string, c Call, users, groups func(*T) *[]string, render func(*T, string, bool, bool) map[string]any) (any, *ipa.IpaError) {
	cn, err := ruleName(c)
	if err != nil {
		return nil, err
	}
	r := rules[cn]
	if r == nil {
		return nil, notFound(cn, kind)
	}
	failed := map[string][][]string{"user": {}, "group": {}}
	completed := 0
	for _, k := range []struct {
		opt string
		has func(string) bool
		dst *[]string
	}{
		{"user", func(n string) bool { return s.users[n] != nil }, users(r)},
		{"group", func(n string) bool { return s.groups[n] != nil }, groups(r)},
	} {
		for _, n := range strs(c.Options[k.opt]) {
			switch {
			case !k.has(n):
				failed[k.opt] = append(failed[k.opt], []string{n, "no such entry"})
			case slices.Contains(*k.dst, n):
				failed[k.opt] = append(failed[k.opt], []string{n, "This entry is already a member"})
			default:
				*k.dst = append(*k.dst, n)
				completed++
			}
		}
	}
	return map[string]any{
		"result":    render(r, cn, true, flag(c, "all")),
		"completed": completed,
		"failed":    map[string]any{"memberuser": failed},
	}, nil
}

// hbactest implements Q35. Called with s.mu held.
func (s *Server) hbactest(c Call) (any, *ipa.IpaError) {
	for _, o := range []string{"user", "targethost", "service"} {
		if str(c.Options[o]) == "" {
			return nil, required(o)
		}
	}
	user, host, svc := str(c.Options["user"]), str(c.Options["targethost"]), str(c.Options["service"])
	var groups, hostGroups []string
	if u := s.users[user]; u != nil {
		groups = s.userGroups(user, u)
		groups = append(groups, s.ancestors(groups)...)
	}
	if h, ok := s.hosts[host]; ok {
		hostGroups = h.HostGroups
	}
	hit := func(cat string, direct []string, name string, indirect []string, ids ...string) bool {
		return cat == "all" || slices.Contains(direct, name) || slices.ContainsFunc(indirect, func(g string) bool { return slices.Contains(ids, g) })
	}

	var names, matched, notMatched, errs []string
	if want, ok := c.Options["rules"]; ok {
		names = strs(want)
	} else {
		for cn, r := range s.hbac {
			if !r.Disabled {
				names = append(names, cn)
			}
		}
	}
	sort.Strings(names)
	for _, cn := range names {
		r := s.hbac[cn]
		switch {
		case r == nil:
			errs = append(errs, cn)
		case hit(r.UserCategory, r.Users, user, groups, r.Groups...) &&
			hit(r.HostCategory, r.Hosts, host, hostGroups, r.HostGroups...) &&
			hit(r.ServiceCategory, r.Services, svc, nil):
			matched = append(matched, cn)
		default:
			notMatched = append(notMatched, cn)
		}
	}
	if len(errs) > 0 {
		return map[string]any{"summary": "Unresolved rules in --rules", "error": errs,
			"matched": nil, "notmatched": nil, "warning": nil, "value": false}, nil
	}
	granted := "False"
	if len(matched) > 0 {
		granted = "True"
	}
	return map[string]any{
		"value":   len(matched) > 0,
		"summary": "Access granted: " + granted,
		"matched": matched, "notmatched": notMatched, "error": errs, "warning": []string(nil),
	}, nil
}

func init() {
	builtins["hbactest"] = (*Server).hbactest

	hbacDesc := func(r *hbacRec) string { return r.Description }
	hbacOff := func(r *hbacRec) bool { return r.Disabled }
	sudoDesc := func(r *sudoRec) string { return r.Description }
	sudoOff := func(r *sudoRec) bool { return r.Disabled }

	builtins["hbacrule_find"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleFind(c, s.hbac, hbacDesc, hbacOff, (*hbacRec).render)
	}
	builtins["sudorule_find"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleFind(c, s.sudo, sudoDesc, sudoOff, (*sudoRec).render)
	}
	builtins["hbacrule_add"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleAdd("HBAC rule", s.hbac, c, func(c Call) *hbacRec {
			return &hbacRec{HBACRule: HBACRule{Description: str(c.Options["description"])}, uuid: newUUID()}
		}, (*hbacRec).render)
	}
	builtins["sudorule_add"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleAdd("sudo rule", s.sudo, c, func(c Call) *sudoRec {
			r := &sudoRec{SudoRule: SudoRule{Description: str(c.Options["description"])}, uuid: newUUID()}
			r.Order, _ = strconv.Atoi(fmt.Sprint(c.Options["sudoorder"]))
			return r
		}, (*sudoRec).render)
	}
	builtins["hbacrule_del"] = func(s *Server, c Call) (any, *ipa.IpaError) { return ruleDel("HBAC rule", s.hbac, c) }
	builtins["sudorule_del"] = func(s *Server, c Call) (any, *ipa.IpaError) { return ruleDel("sudo rule", s.sudo, c) }
	builtins["hbacrule_add_user"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleAddUser(s, s.hbac, "HBAC rule", c,
			func(r *hbacRec) *[]string { return &r.Users }, func(r *hbacRec) *[]string { return &r.Groups }, (*hbacRec).render)
	}
	builtins["sudorule_add_user"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleAddUser(s, s.sudo, "sudo rule", c,
			func(r *sudoRec) *[]string { return &r.Users }, func(r *sudoRec) *[]string { return &r.Groups }, (*sudoRec).render)
	}
	builtins["sudorule_add_option"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, err := ruleName(c)
		if err != nil {
			return nil, err
		}
		r := s.sudo[cn]
		if r == nil {
			return nil, notFound(cn, "sudo rule")
		}
		opt := str(c.Options["ipasudoopt"])
		if opt == "" {
			return nil, required("ipasudoopt")
		}
		if !slices.Contains(r.Options, opt) {
			r.Options = append(r.Options, opt)
		}
		return entry(cn, r.render(cn, false, flag(c, "all")), fmt.Sprintf("Added option %q to Sudo Rule %q", opt, cn)), nil
	}
}
