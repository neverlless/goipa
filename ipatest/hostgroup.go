// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	ipa "github.com/neverlless/goipa"
)

const hostGroupBaseDN = "cn=hostgroups,cn=accounts,dc=test,dc=local"

// HostGroup is a host group of the fake server. A host is also a member when
// its Host.HostGroups name the group.
type HostGroup struct {
	Description   string
	Hosts         []string // member_host
	HostGroups    []string // member_hostgroup
	ManagerUsers  []string // membermanager_user
	ManagerGroups []string // membermanager_group
}

func (g HostGroup) clone() HostGroup {
	g.Hosts = cloneStrs(g.Hosts)
	g.HostGroups = cloneStrs(g.HostGroups)
	g.ManagerUsers = cloneStrs(g.ManagerUsers)
	g.ManagerGroups = cloneStrs(g.ManagerGroups)
	return g
}

// hostGroupKey is how FreeIPA keeps a host group name, wherever it is
// named (Q51).
func hostGroupKey(n string) string { return strings.ToLower(n) }

// lowerHostGroups lower-cases the host group names in l in place.
func lowerHostGroups(l []string) {
	for i, n := range l {
		l[i] = hostGroupKey(n)
	}
}

// AddHostGroup creates or replaces host group cn; the name, and the names of
// its nested groups, are lower-cased, as FreeIPA does (Q51).
func (s *Server) AddHostGroup(cn string, g HostGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g = g.clone()
	lowerHostGroups(g.HostGroups)
	s.hostgroups[hostGroupKey(cn)] = &g
}

// HostGroup returns a copy of host group cn.
func (s *Server) HostGroup(cn string) (HostGroup, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.hostgroups[hostGroupKey(cn)]
	if !ok {
		return HostGroup{}, false
	}
	return g.clone(), true
}

// hostGroupHosts is member_host: HostGroup.Hosts plus hosts whose
// Host.HostGroups name cn.
func (s *Server) hostGroupHosts(cn string) []string {
	var out []string
	if g := s.hostgroups[cn]; g != nil {
		out = slices.Clone(g.Hosts)
	}
	var extra []string
	for fqdn, h := range s.hosts {
		if slices.Contains(h.HostGroups, cn) && !slices.Contains(out, fqdn) {
			extra = append(extra, fqdn)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// hostGroupsOf is a host's memberof_hostgroup.
func (s *Server) hostGroupsOf(fqdn string) []string {
	out := slices.Clone(s.hosts[fqdn].HostGroups)
	var extra []string
	for cn, g := range s.hostgroups {
		if slices.Contains(g.Hosts, fqdn) && !slices.Contains(out, cn) {
			extra = append(extra, cn)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func (s *Server) hostGroupParents(cn string) []string {
	var out []string
	for p, g := range s.hostgroups {
		if slices.Contains(g.HostGroups, cn) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) hostGroupAncestors(cns []string) []string {
	return walk(cns, s.hostGroupParents)
}

func (s *Server) renderHostGroup(cn string, g *HostGroup, members, all bool) map[string]any {
	out := map[string]any{"cn": []string{cn}}
	if g.Description != "" {
		out["description"] = []string{g.Description}
	}
	if all {
		out["objectclass"] = []string{"ipaobject", "ipahostgroup", "nestedGroup", "groupOfNames", "top", "mepOriginEntry"}
		out["dn"] = "cn=" + cn + "," + hostGroupBaseDN
	}
	set := func(k string, v []string) {
		if len(v) > 0 {
			out[k] = slices.Clone(v) // writeEnvelope marshals after s.mu is released
		}
	}
	if members {
		hosts := s.hostGroupHosts(cn)
		kids := func(n string) []string {
			if g := s.hostgroups[n]; g != nil {
				return g.HostGroups
			}
			return nil
		}
		nested := walk([]string{cn}, kids)
		if slices.ContainsFunc(nested, func(n string) bool { return slices.Contains(kids(n), cn) }) {
			nested = append(nested, cn) // FreeIPA accepts cycles and lists the group in its own memberindirect (Q140)
		}
		var nestedHosts []string
		for _, n := range nested {
			for _, h := range s.hostGroupHosts(n) {
				if !slices.Contains(nestedHosts, h) {
					nestedHosts = append(nestedHosts, h)
				}
			}
		}
		sort.Strings(nestedHosts)
		set("member_host", hosts)
		set("member_hostgroup", g.HostGroups)
		set("memberindirect_host", without(nestedHosts, hosts))
		set("memberindirect_hostgroup", without(nested, g.HostGroups))
		parents := s.hostGroupParents(cn)
		set("memberof_hostgroup", parents)
		set("memberofindirect_hostgroup", without(s.hostGroupAncestors(parents), []string{cn}))
		set("membermanager_user", g.ManagerUsers)
		set("membermanager_group", g.ManagerGroups)
	}
	return out
}

func (s *Server) hostGroupArg(c Call) (string, *HostGroup, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", nil, required("cn")
	}
	cn := hostGroupKey(c.Args[0])
	g := s.hostgroups[cn]
	if g == nil {
		return "", nil, notFound(cn, "host group")
	}
	return cn, g, nil
}

func hostGroupShow(s *Server, c Call) (any, *ipa.IpaError) {
	cn, g, err := s.hostGroupArg(c)
	if err != nil {
		return nil, err
	}
	all := flag(c, "all")
	return entry(cn, s.renderHostGroup(cn, g, all || !flag(c, "no_members"), all), ""), nil
}

func hostGroupFind(s *Server, c Call) (any, *ipa.IpaError) {
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
	for cn, g := range s.hostgroups {
		if needle != "" && !strings.Contains(strings.ToLower(cn), needle) && !strings.Contains(strings.ToLower(g.Description), needle) {
			continue
		}
		if !matches(c, "cn", cn) || !matches(c, "description", g.Description) {
			continue
		}
		cns = append(cns, cn)
	}
	sort.Strings(cns)
	recs := make([]map[string]any, 0, len(cns))
	for _, cn := range cns {
		recs = append(recs, s.renderHostGroup(cn, s.hostgroups[cn], members, all))
	}
	return listLimited(c, recs), nil
}

func hostGroupAdd(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("cn")
	}
	cn := hostGroupKey(c.Args[0])
	if err := s.refuse(c, true, noAdd("cn="+cn+","+hostGroupBaseDN)); err != nil {
		return nil, err
	}
	if s.hostgroups[cn] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("host group with name %q already exists", cn)}
	}
	g := &HostGroup{Description: str(c.Options["description"])}
	s.hostgroups[cn] = g
	return entry(cn, s.renderHostGroup(cn, g, true, flag(c, "all")), fmt.Sprintf("Added hostgroup %q", cn)), nil
}

// dropName removes n from l in place, as a deleted entry leaves the member
// lists that named it.
func dropName(l []string, n string) []string {
	return slices.DeleteFunc(l, func(m string) bool { return m == n })
}

func hostGroupDel(s *Server, c Call) (any, *ipa.IpaError) {
	deleted := make([]string, len(c.Args))
	for i, cn := range c.Args {
		deleted[i] = hostGroupKey(cn)
		if s.hostgroups[deleted[i]] == nil {
			return nil, notFound(cn, "host group")
		}
	}
	if len(deleted) > 0 {
		if err := s.refuse(c, true, noDelete("cn="+deleted[0]+","+hostGroupBaseDN)); err != nil {
			return nil, err
		}
	}
	for _, cn := range deleted {
		delete(s.hostgroups, cn)
		for _, g := range s.hostgroups {
			g.HostGroups = dropName(g.HostGroups, cn)
		}
		for fqdn, h := range s.hosts {
			if slices.Contains(h.HostGroups, cn) {
				h.HostGroups = dropName(slices.Clone(h.HostGroups), cn)
				s.hosts[fqdn] = h
			}
		}
		for _, r := range s.hbac {
			r.HostGroups = dropName(r.HostGroups, cn)
		}
		for _, r := range s.sudo {
			r.HostGroups = dropName(r.HostGroups, cn)
		}
		for _, v := range s.services {
			v.KeytabRetrieve.HostGroups = dropName(v.KeytabRetrieve.HostGroups, cn)
			v.KeytabCreate.HostGroups = dropName(v.KeytabCreate.HostGroups, cn)
		}
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   deleted,
		"summary": fmt.Sprintf("Deleted hostgroup %q", strings.Join(deleted, ",")),
	}, nil
}

// hostGroupMemberCmd implements hostgroup_{add,remove}_member and the
// _member_manager twins; per-member problems come back in failed (U3).
func hostGroupMemberCmd(add, managers bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, g, err := s.hostGroupArg(c)
		if err != nil {
			return nil, err
		}
		key, kinds := "member", [2]string{"host", "hostgroup"}
		lists := map[string]*[]string{"host": &g.Hosts, "hostgroup": &g.HostGroups}
		exists := map[string]func(string) bool{
			"host":      func(n string) bool { _, ok := s.hosts[n]; return ok },
			"hostgroup": func(n string) bool { return s.hostgroups[n] != nil },
		}
		isMember := map[string]func(string) bool{
			"host":      func(n string) bool { return slices.Contains(s.hostGroupHosts(cn), n) },
			"hostgroup": func(n string) bool { return slices.Contains(g.HostGroups, n) },
		}
		if managers {
			key, kinds = "membermanager", [2]string{"user", "group"}
			lists = map[string]*[]string{"user": &g.ManagerUsers, "group": &g.ManagerGroups}
			exists = map[string]func(string) bool{
				"user":  func(n string) bool { return s.users[n] != nil },
				"group": func(n string) bool { return s.groups[n] != nil },
			}
			isMember = map[string]func(string) bool{
				"user":  func(n string) bool { return slices.Contains(g.ManagerUsers, n) },
				"group": func(n string) bool { return slices.Contains(g.ManagerGroups, n) },
			}
		}
		mine := s.groupsOf(c.User)
		allowed := s.isAdmin(c.User) || !managers && (s.holds(c.User, "Host Group Administrators") || slices.Contains(g.ManagerUsers, c.User) ||
			slices.ContainsFunc(g.ManagerGroups, func(n string) bool { return slices.Contains(mine, n) }))
		attr := map[bool]string{false: "member", true: "memberManager"}[managers]
		denied := fmt.Sprintf("Insufficient access: Insufficient 'write' privilege to the '%s' attribute of entry 'cn=%s,%s'.", attr, cn, hostGroupBaseDN)
		failed := map[string][][]string{kinds[0]: {}, kinds[1]: {}}
		completed := 0
		for _, kind := range kinds {
			list := lists[kind]
			for _, given := range strs(c.Options[kind]) {
				n := given
				if !managers && kind == "hostgroup" {
					n = hostGroupKey(n)
				}
				msg := ""
				switch {
				case !allowed:
					msg = denied
				case !add && !managers && !isMember[kind](n): // FreeIPA does not look a removed member up (Q141)
					msg = "This entry is not a member"
				case !exists[kind](n):
					msg = "no such entry"
				case add && !managers && kind == "hostgroup" && n == cn:
					msg = "A group may not be added as a member of itself"
				case add && isMember[kind](n):
					msg = "This entry is already a member"
				case !add && !isMember[kind](n):
					msg = "This entry is not a member"
				}
				if msg != "" {
					failed[kind] = append(failed[kind], []string{given, msg}) // spelled as given (Q141)
					continue
				}
				completed++
				if add {
					*list = append(*list, n)
					continue
				}
				*list = slices.DeleteFunc(*list, func(m string) bool { return m == n })
				if kind == "host" { // the membership may live in Host.HostGroups
					h := s.hosts[n]
					h.HostGroups = slices.DeleteFunc(slices.Clone(h.HostGroups), func(m string) bool { return m == cn })
					s.hosts[n] = h
				}
			}
		}
		return map[string]any{
			"result":    s.renderHostGroup(cn, g, true, flag(c, "all")),
			"completed": completed,
			"failed":    map[string]map[string][][]string{key: failed},
		}, nil
	}
}

func init() {
	builtins["hostgroup_show"] = hostGroupShow
	builtins["hostgroup_find"] = hostGroupFind
	builtins["hostgroup_add"] = hostGroupAdd
	builtins["hostgroup_del"] = hostGroupDel
	builtins["hostgroup_add_member"] = hostGroupMemberCmd(true, false)
	builtins["hostgroup_remove_member"] = hostGroupMemberCmd(false, false)
	builtins["hostgroup_add_member_manager"] = hostGroupMemberCmd(true, true)
	builtins["hostgroup_remove_member_manager"] = hostGroupMemberCmd(false, true)
}
