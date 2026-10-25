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
	RunAsUsers, RunAsUserGroups, RunAsGroups                                       []string
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
	ext  map[string]*[]string // external members by attribute, Q81
}

func (r HBACRule) clone() HBACRule {
	for _, p := range []*[]string{&r.Users, &r.Groups, &r.Hosts, &r.HostGroups, &r.Services, &r.ServiceGroups} {
		*p = cloneStrs(*p)
	}
	return r
}

func (r SudoRule) clone() SudoRule {
	for _, p := range []*[]string{&r.Users, &r.Groups, &r.Hosts, &r.HostGroups, &r.AllowCommands, &r.AllowCommandGroups,
		&r.DenyCommands, &r.DenyCommandGroups, &r.RunAsUsers, &r.RunAsUserGroups, &r.RunAsGroups, &r.Options} {
		*p = cloneStrs(*p)
	}
	return r
}

// AddHBACRule creates or replaces HBAC rule cn. New servers already hold
// allow_all, as every FreeIPA does.
func (s *Server) AddHBACRule(cn string, r HBACRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := &hbacRec{HBACRule: r.clone(), uuid: newUUID()}
	lowerHostGroups(rec.HostGroups)
	s.hbac[cn] = rec
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
	rec := &sudoRec{SudoRule: r.clone(), uuid: newUUID()}
	lowerHostGroups(rec.HostGroups)
	s.sudo[cn] = rec
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
			"ipasudorunas_user": r.RunAsUsers, "ipasudorunas_group": r.RunAsUserGroups, "ipasudorunasgroup_group": r.RunAsGroups,
		}, members, all, "ipaUniqueID="+r.uuid+",cn=sudorules,cn=sudo,dc=test,dc=local", "ipaassociation", "ipasudorule")
	if len(r.Options) > 0 {
		out["ipasudoopt"] = slices.Clone(r.Options)
	}
	if r.Order > 0 {
		out["sudoorder"] = []string{strconv.Itoa(r.Order)}
	}
	for k, v := range r.ext {
		if len(*v) > 0 {
			out[k] = slices.Clone(*v)
		}
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
	if _, ok := s.hosts[host]; ok {
		hostGroups = s.hostGroupsOf(host)
		hostGroups = append(hostGroups, s.hostGroupAncestors(hostGroups)...)
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
			return &hbacRec{HBACRule: HBACRule{Description: str(c.Options["description"]), UserCategory: str(c.Options["usercategory"]),
				HostCategory: str(c.Options["hostcategory"]), ServiceCategory: str(c.Options["servicecategory"])}, uuid: newUUID()}
		}, (*hbacRec).render)
	}
	builtins["sudorule_add"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleAdd("sudo rule", s.sudo, c, func(c Call) *sudoRec {
			r := &sudoRec{SudoRule: SudoRule{Description: str(c.Options["description"]),
				UserCategory: str(c.Options["usercategory"]), HostCategory: str(c.Options["hostcategory"]),
				CmdCategory: str(c.Options["cmdcategory"]), RunAsUserCategory: str(c.Options["ipasudorunasusercategory"]),
				RunAsGroupCategory: str(c.Options["ipasudorunasgroupcategory"])}, uuid: newUUID()}
			r.Order, _ = strconv.Atoi(fmt.Sprint(c.Options["sudoorder"]))
			return r
		}, (*sudoRec).render)
	}
	builtins["hbacrule_del"] = func(s *Server, c Call) (any, *ipa.IpaError) { return ruleDel("HBAC rule", s.hbac, c) }
	builtins["sudorule_del"] = func(s *Server, c Call) (any, *ipa.IpaError) { return ruleDel("sudo rule", s.sudo, c) }
	builtins["hbacrule_add_user"] = hbacMembers("user", true)
	builtins["sudorule_add_user"] = sudoMember(true, sudoUsers)
	builtins["sudorule_add_option"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, err := ruleName(c)
		if err != nil {
			return nil, err
		}
		r := s.sudo[cn]
		if r == nil {
			return nil, notFound(cn, "sudo rule")
		}
		opts, err := s.sudoOpts(c)
		if err != nil {
			return nil, err
		}
		for _, opt := range opts {
			if slices.Contains(r.Options, opt) {
				return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: "This entry already exists"} // Q82
			}
		}
		r.Options = append(r.Options, opts...)
		return entry(cn, r.render(cn, !flag(c, "no_members"), flag(c, "all")), fmt.Sprintf("Added option %q to Sudo Rule %q", strings.Join(opts, ","), cn)), nil
	}
}

// HBACRule returns a copy of HBAC rule cn.
func (s *Server) HBACRule(cn string) (HBACRule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hbac[cn]
	if !ok {
		return HBACRule{}, false
	}
	return r.HBACRule.clone(), true
}

// SudoRule returns a copy of sudo rule cn; external members (Q81) are not
// part of it.
func (s *Server) SudoRule(cn string) (SudoRule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.sudo[cn]
	if !ok {
		return SudoRule{}, false
	}
	return r.SudoRule.clone(), true
}
