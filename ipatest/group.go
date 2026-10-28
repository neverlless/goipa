// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	ipa "github.com/neverlless/goipa"
)

const groupBaseDN = "cn=groups,cn=accounts,dc=test,dc=local"

// Group is a user group of the fake server. The zero value is a POSIX group,
// FreeIPA's default.
type Group struct {
	Description   string
	GID           string   // gidnumber; "" on a POSIX group is replaced by the next free one
	Members       []string // member_user
	MemberGroups  []string // member_group
	ManagerUsers  []string // membermanager_user
	ManagerGroups []string // membermanager_group
	External      bool     // ipaexternalgroup
	NonPOSIX      bool     // no posixgroup objectclass, no gidnumber
}

type groupRec struct {
	Group
	uuid string
}

func (g Group) clone() Group {
	g.Members = cloneStrs(g.Members)
	g.MemberGroups = cloneStrs(g.MemberGroups)
	g.ManagerUsers = cloneStrs(g.ManagerUsers)
	g.ManagerGroups = cloneStrs(g.ManagerGroups)
	return g
}

func (g Group) posix() bool { return !g.NonPOSIX && !g.External }

// AddGroup creates or replaces group cn. A POSIX group without GID gets the
// next gidnumber.
func (s *Server) AddGroup(cn string, g Group) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putGroup(cn, g)
}

// putGroup needs s.mu held. A replaced group keeps its ids.
func (s *Server) putGroup(cn string, g Group) *groupRec {
	g = g.clone()
	if g.posix() && g.GID == "" {
		s.nextGID++
		g.GID = strconv.Itoa(s.nextGID)
	}
	r := s.groups[cn]
	if r == nil {
		r = &groupRec{uuid: newUUID()}
		s.groups[cn] = r
	}
	r.Group = g
	return r
}

// Group returns a copy of group cn.
func (s *Server) Group(cn string) (Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.groups[cn]
	if !ok {
		return Group{}, false
	}
	return r.Group.clone(), true
}

// groupUsers is member_user: Group.Members plus users whose User.Groups name
// the group (R2).
func (s *Server) groupUsers(cn string) []string {
	var out []string
	if r := s.groups[cn]; r != nil {
		out = slices.Clone(r.Members)
	}
	var extra []string
	for uid, u := range s.users {
		if slices.Contains(u.Groups, cn) && !slices.Contains(out, uid) {
			extra = append(extra, uid)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// userGroups is memberof_group: User.Groups plus groups listing the user.
func (s *Server) userGroups(uid string, u *userRec) []string {
	out := slices.Clone(u.Groups)
	var extra []string
	for cn, g := range s.groups {
		if slices.Contains(g.Members, uid) && !slices.Contains(out, cn) {
			extra = append(extra, cn)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// walk returns the groups reachable from start through next, start excluded.
func walk(start []string, next func(string) []string) []string {
	seen := map[string]bool{}
	queue := slices.Clone(start)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, m := range next(n) {
			if !seen[m] {
				seen[m] = true
				queue = append(queue, m)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		if !slices.Contains(start, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ancestors are the groups that contain any of cns through nesting, cns excluded.
func (s *Server) ancestors(cns []string) []string {
	return walk(cns, func(cn string) []string {
		var out []string
		for p, g := range s.groups {
			if slices.Contains(g.MemberGroups, cn) {
				out = append(out, p)
			}
		}
		return out
	})
}

func (s *Server) descendants(cn string) []string {
	return walk([]string{cn}, func(n string) []string {
		if g := s.groups[n]; g != nil {
			return g.MemberGroups
		}
		return nil
	})
}

func without(all, drop []string) []string {
	return slices.DeleteFunc(slices.Clone(all), func(s string) bool { return slices.Contains(drop, s) })
}

func (s *Server) renderGroup(cn string, r *groupRec, members, all bool) map[string]any {
	out := map[string]any{
		"cn": []string{cn},
	}
	if r.Description != "" {
		out["description"] = []string{r.Description}
	}
	if r.posix() {
		out["gidnumber"] = []string{r.GID}
	}
	if all {
		oc := []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject"}
		if r.posix() {
			oc = append(oc, "posixgroup")
		}
		if r.External {
			oc = append(oc, "ipaexternalgroup")
		}
		out["objectclass"] = oc
		out["ipauniqueid"] = []string{r.uuid}
		out["dn"] = "cn=" + cn + "," + groupBaseDN
	}
	set := func(k string, v []string) {
		if len(v) > 0 {
			out[k] = slices.Clone(v) // writeEnvelope marshals after s.mu is released
		}
	}
	var parents []string
	for p, g := range s.groups {
		if slices.Contains(g.MemberGroups, cn) {
			parents = append(parents, p)
		}
	}
	sort.Strings(parents)
	set("memberof_group", parents)
	if members {
		users := s.groupUsers(cn)
		nested := s.descendants(cn)
		var nestedUsers []string
		for _, n := range nested {
			for _, u := range s.groupUsers(n) {
				if !slices.Contains(nestedUsers, u) {
					nestedUsers = append(nestedUsers, u)
				}
			}
		}
		set("member_user", users)
		set("member_group", r.MemberGroups)
		set("memberindirect_user", without(nestedUsers, users))
		set("memberindirect_group", without(nested, r.MemberGroups))
		set("membermanager_user", r.ManagerUsers)
		set("membermanager_group", r.ManagerGroups)
	}
	return out
}

func (s *Server) groupArg(c Call) (string, *groupRec, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", nil, required("cn")
	}
	cn := c.Args[0]
	r := s.groups[cn]
	if r == nil {
		return "", nil, notFound(cn, "group")
	}
	return cn, r, nil
}

// gidOpt reads gidnumber, which clients send as a string or a number.
func gidOpt(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return str(v)
}

func groupShow(s *Server, c Call) (any, *ipa.IpaError) {
	cn, r, err := s.groupArg(c)
	if err != nil {
		return nil, err
	}
	all := flag(c, "all")
	return entry(cn, s.renderGroup(cn, r, all || !flag(c, "no_members"), all), ""), nil
}

func groupFind(s *Server, c Call) (any, *ipa.IpaError) {
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
	for cn, r := range s.groups {
		if needle != "" && !strings.Contains(strings.ToLower(cn), needle) && !strings.Contains(strings.ToLower(r.Description), needle) {
			continue
		}
		if !matches(c, "cn", cn) || !matches(c, "description", r.Description) {
			continue
		}
		cns = append(cns, cn)
	}
	sort.Strings(cns)
	recs := make([]map[string]any, 0, len(cns))
	for _, cn := range cns {
		recs = append(recs, s.renderGroup(cn, s.groups[cn], members, all))
	}
	return listLimited(c, recs), nil
}

func groupAdd(s *Server, c Call) (any, *ipa.IpaError) {
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("cn")
	}
	cn := c.Args[0]
	if err := s.refuse(c, true, noAdd("cn="+cn+","+groupBaseDN)); err != nil {
		return nil, err
	}
	if s.groups[cn] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("group with name %q already exists", cn)}
	}
	g := Group{
		Description: str(c.Options["description"]),
		GID:         gidOpt(c.Options["gidnumber"]),
		External:    flag(c, "external"),
	}
	g.NonPOSIX = flag(c, "nonposix") && !g.External
	if !g.posix() {
		g.GID = ""
	}
	r := s.putGroup(cn, g)
	return entry(cn, s.renderGroup(cn, r, true, flag(c, "all")), fmt.Sprintf("Added group %q", cn)), nil
}

func groupMod(s *Server, c Call) (any, *ipa.IpaError) {
	cn, r, err := s.groupArg(c)
	if err != nil {
		return nil, err
	}
	if err := s.refuse(c, true, noWrite(firstAttr(c), "cn="+cn+","+groupBaseDN)); err != nil {
		return nil, err
	}
	next := r.Group.clone()
	if v, ok := c.Options["description"]; ok {
		next.Description = str(v)
	}
	if v, ok := c.Options["gidnumber"]; ok && next.posix() {
		next.GID = gidOpt(v)
	}
	if reflect.DeepEqual(next, r.Group) {
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	r.Group = next
	return entry(cn, s.renderGroup(cn, r, true, flag(c, "all")), fmt.Sprintf("Modified group %q", cn)), nil
}

func groupDel(s *Server, c Call) (any, *ipa.IpaError) {
	for _, cn := range c.Args {
		if s.groups[cn] == nil {
			return nil, notFound(cn, "group")
		}
	}
	if len(c.Args) > 0 {
		if err := s.refuse(c, true, noDelete("cn="+c.Args[0]+","+groupBaseDN)); err != nil {
			return nil, err
		}
	}
	deleted := slices.Clone(c.Args)
	for _, cn := range deleted {
		delete(s.groups, cn)
		delete(s.pwpol, cn)
		s.dropFromRules(cn, true)
		for _, g := range s.groups {
			g.MemberGroups = slices.DeleteFunc(g.MemberGroups, func(n string) bool { return n == cn })
			g.ManagerGroups = slices.DeleteFunc(g.ManagerGroups, func(n string) bool { return n == cn })
		}
		for _, u := range s.users {
			u.Groups = slices.DeleteFunc(u.Groups, func(n string) bool { return n == cn })
		}
	}
	if deleted == nil {
		deleted = []string{}
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   deleted,
		"summary": fmt.Sprintf("Deleted group %q", strings.Join(deleted, ",")),
	}, nil
}

// groupsOf is uid's groups, nested ones included.
func (s *Server) groupsOf(uid string) []string {
	var mine []string
	if u := s.users[uid]; u != nil {
		mine = s.userGroups(uid, u)
	}
	return append(mine, s.ancestors(mine)...)
}

// isAdmin is true for uid admin and members of the group admins.
func (s *Server) isAdmin(uid string) bool {
	return uid == "admin" || slices.Contains(s.groupsOf(uid), "admins")
}

// canWrite reports whether uid may change the members of r. Member managers
// may change members; only admins may change the managers.
func (s *Server) canWrite(uid, cn string, r *groupRec, managers bool) bool {
	if s.isAdmin(uid) || !managers && s.holds(uid, "Group Administrators", "Modify Group membership") {
		return true
	}
	mine := s.groupsOf(uid)
	return !managers && (slices.Contains(r.ManagerUsers, uid) || slices.ContainsFunc(r.ManagerGroups, func(g string) bool { return slices.Contains(mine, g) }))
}

// memberCmd implements group_{add,remove}_member and the _member_manager
// twins. Per-member problems, ACI denials included, come back in failed
// next to result, not as an error (U3).
func memberCmd(add, managers bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, r, err := s.groupArg(c)
		if err != nil {
			return nil, err
		}
		key, users, groups := "member", &r.Members, &r.MemberGroups
		if managers {
			key, users, groups = "membermanager", &r.ManagerUsers, &r.ManagerGroups
		}
		allowed := s.canWrite(c.User, cn, r, managers)
		denied := fmt.Sprintf("Insufficient access: Insufficient 'write' privilege to the '%s' attribute of entry 'cn=%s,%s'.", strings.TrimSuffix(key, "manager"), cn, groupBaseDN)
		failed := map[string][][]string{"user": {}, "group": {}}
		completed := 0
		for _, kind := range []string{"user", "group"} {
			list, exists := groups, func(n string) bool { return s.groups[n] != nil }
			isMember := func(n string) bool { return slices.Contains(*list, n) }
			if kind == "user" {
				list, exists = users, func(n string) bool { return s.users[n] != nil }
				if !managers {
					isMember = func(n string) bool { return slices.Contains(s.groupUsers(cn), n) }
				}
			}
			for _, n := range strs(c.Options[kind]) {
				msg := ""
				switch {
				case !allowed:
					msg = denied
				case !exists(n):
					msg = "no such entry"
				case add && !managers && kind == "group" && n == cn:
					msg = "A group may not be added as a member of itself"
				case add && isMember(n):
					msg = "This entry is already a member"
				case !add && !isMember(n):
					msg = "This entry is not a member"
				}
				if msg != "" {
					failed[kind] = append(failed[kind], []string{n, msg})
					continue
				}
				completed++
				switch {
				case add:
					*list = append(*list, n)
				case kind == "user" && !managers: // R2: membership is also in User.Groups
					*list = slices.DeleteFunc(*list, func(m string) bool { return m == n })
					s.users[n].Groups = slices.DeleteFunc(s.users[n].Groups, func(g string) bool { return g == cn })
				default:
					*list = slices.DeleteFunc(*list, func(m string) bool { return m == n })
				}
			}
		}
		fail := map[string]map[string][][]string{key: failed}
		if !managers {
			failed["service"], failed["idoverrideuser"] = [][]string{}, [][]string{}
		}
		return map[string]any{
			"result":    s.renderGroup(cn, r, true, flag(c, "all")),
			"completed": completed,
			"failed":    fail,
		}, nil
	}
}

func init() {
	builtins["group_show"] = groupShow
	builtins["group_find"] = groupFind
	builtins["group_add"] = groupAdd
	builtins["group_mod"] = groupMod
	builtins["group_del"] = groupDel
	builtins["group_add_member"] = memberCmd(true, false)
	builtins["group_remove_member"] = memberCmd(false, false)
	builtins["group_add_member_manager"] = memberCmd(true, true)
	builtins["group_remove_member_manager"] = memberCmd(false, true)
}
