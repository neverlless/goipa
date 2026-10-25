// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"slices"
	"sort"
	"strings"

	ipa "github.com/neverlless/goipa"
)

const (
	roleBaseDN       = "cn=roles,cn=accounts,dc=test,dc=local"
	privilegeBaseDN  = "cn=privileges,cn=pbac,dc=test,dc=local"
	permissionBaseDN = "cn=permissions,cn=pbac,dc=test,dc=local"
)

// AddRole creates or replaces role cn; r.Name is ignored. The fake does not
// link roles and privileges: set r.Privileges and the privilege's Roles both.
// New servers hold FreeIPA's "User Administrator" role.
func (s *Server) AddRole(cn string, r ipa.Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[cn] = cloneRole(r)
}

// AddPrivilege creates or replaces privilege cn; p.Name is ignored. New
// servers hold FreeIPA's "User Administrators" privilege.
func (s *Server) AddPrivilege(cn string, p ipa.Privilege) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.Permissions, p.Roles = cloneStrs(p.Permissions), cloneStrs(p.Roles)
	s.privs[cn] = &p
}

// AddPermission creates or replaces permission cn; p.Name is ignored. New
// servers hold FreeIPA's "System: Add Users" permission.
func (s *Server) AddPermission(cn string, p ipa.Permission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.Rights, p.Attrs, p.Filters, p.Privileges = cloneStrs(p.Rights), cloneStrs(p.Attrs), cloneStrs(p.Filters), cloneStrs(p.Privileges)
	s.perms[cn] = &p
}

func cloneRole(r ipa.Role) *ipa.Role {
	for _, l := range []*[]string{&r.Users, &r.Groups, &r.Hosts, &r.HostGroups, &r.Services, &r.Privileges} {
		*l = cloneStrs(*l)
	}
	return &r
}

// The builtins as FreeIPA 4.13.4 ships them (4.9.13 and 4.12.2 match),
// reduced to the fields the ipa types carry (Q120).
func seedRoles() map[string]*ipa.Role {
	return map[string]*ipa.Role{"User Administrator": {
		Description: "Responsible for creating Users and Groups",
		Privileges:  []string{"User Administrators", "Group Administrators", "Stage User Administrators", "Subordinate ID Administrators"},
	}}
}

func seedPrivileges() map[string]*ipa.Privilege {
	return map[string]*ipa.Privilege{"User Administrators": {
		Description: "User Administrators",
		Permissions: []string{"System: Read Radius Servers", "System: Manage Subordinate Ids", "System: Remove Subordinate Ids",
			"System: Add User to default group", "System: Add Users", "System: Change User password",
			"System: Manage User Certificates", "System: Manage User Principals", "System: Manage User SSH Public Keys",
			"System: Modify Users", "System: Read UPG Definition", "System: Read User Kerberos Login Attributes",
			"System: Remove Users", "System: Unlock User"},
		Roles: []string{"User Administrator"},
	}}
}

func seedPermissions() map[string]*ipa.Permission {
	return map[string]*ipa.Permission{"System: Add Users": {
		Rights:     []string{"add"},
		Type:       "user",
		BindType:   "permission",
		Location:   baseDN,
		Filters:    []string{"(objectclass=posixaccount)"},
		Privileges: []string{"User Administrators"},
	}}
}

// rbacRec renders the attributes every rbac object shares.
func rbacRec(cn, desc, base string, objectclass []string, all bool) map[string]any {
	out := map[string]any{"cn": []string{cn}}
	if desc != "" {
		out["description"] = []string{desc}
	}
	if all {
		out["objectclass"] = objectclass
		out["dn"] = "cn=" + cn + "," + base
	}
	return out
}

func setStrs(out map[string]any, k string, v []string) {
	if len(v) > 0 {
		out[k] = slices.Clone(v) // writeEnvelope marshals after s.mu is released
	}
}

func renderRole(r *ipa.Role, cn string, members, all bool) map[string]any {
	out := rbacRec(cn, r.Description, roleBaseDN, []string{"groupofnames", "nestedgroup", "top"}, all)
	if members {
		setStrs(out, "member_user", r.Users)
		setStrs(out, "member_group", r.Groups)
		setStrs(out, "member_host", r.Hosts)
		setStrs(out, "member_hostgroup", r.HostGroups)
		setStrs(out, "member_service", r.Services)
		setStrs(out, "memberof_privilege", r.Privileges)
	}
	return out
}

func renderPrivilege(p *ipa.Privilege, cn string, members, all bool) map[string]any {
	out := rbacRec(cn, p.Description, privilegeBaseDN, []string{"top", "groupofnames", "nestedgroup"}, all)
	if members {
		setStrs(out, "memberof_permission", p.Permissions)
		setStrs(out, "member_role", p.Roles)
	}
	return out
}

func renderPermission(p *ipa.Permission, cn string, members, all bool) map[string]any {
	out := rbacRec(cn, "", permissionBaseDN, []string{"top", "groupofnames", "ipapermission", "ipapermissionv2"}, all)
	setStrs(out, "ipapermright", p.Rights)
	setStrs(out, "attrs", p.Attrs)
	setStrs(out, "ipapermtargetfilter", p.Filters)
	for k, v := range map[string]string{"type": p.Type, "ipapermbindruletype": p.BindType, "ipapermlocation": p.Location, "targetgroup": p.TargetGroup} {
		if v != "" {
			out[k] = []string{v}
		}
	}
	if members {
		setStrs(out, "member_privilege", p.Privileges)
	}
	return out
}

func rbacShow[T any](kind string, recs map[string]*T, render func(*T, string, bool, bool) map[string]any) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, err := ruleName(c)
		if err != nil {
			return nil, err
		}
		r := recs[cn]
		if r == nil || !s.isAdmin(c.User) { // Q122: the read permissions are privilege-bound
			return nil, notFound(cn, kind)
		}
		all := flag(c, "all")
		return entry(cn, render(r, cn, all || !flag(c, "no_members"), all), ""), nil
	}
}

// rbacFind matches the criteria against cn and description ignoring case,
// the cn option exactly but ignoring case (Q153), and the description and
// type options exactly.
func rbacFind[T any](recs map[string]*T, desc, typ func(*T) string, render func(*T, string, bool, bool) map[string]any) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
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
		for cn, r := range recs {
			if !s.isAdmin(c.User) { // Q122
				break
			}
			d := desc(r)
			if needle != "" && !strings.Contains(strings.ToLower(cn), needle) && !strings.Contains(strings.ToLower(d), needle) {
				continue
			}
			if v, ok := c.Options["cn"]; ok && !strings.EqualFold(str(v), cn) {
				continue
			}
			if matches(c, "description", d) && matches(c, "type", typ(r)) {
				cns = append(cns, cn)
			}
		}
		sort.Strings(cns)
		out := make([]map[string]any, 0, len(cns))
		for _, cn := range cns {
			out = append(out, render(recs[cn], cn, members, all))
		}
		return listLimited(c, out), nil
	}
}

// roleAddMember is role_add_member for users, groups and hosts; the other
// member kinds always fail as "no such entry" (Q121).
func roleAddMember(s *Server, c Call) (any, *ipa.IpaError) {
	cn, err := ruleName(c)
	if err != nil {
		return nil, err
	}
	r := s.roles[cn]
	if r == nil {
		return nil, notFound(cn, "role")
	}
	failed := map[string][][]string{}
	completed := 0
	for _, k := range []struct {
		opt string
		has func(string) bool
		dst *[]string
	}{
		{"user", func(n string) bool { return s.users[n] != nil }, &r.Users},
		{"group", func(n string) bool { return s.groups[n] != nil }, &r.Groups},
		{"host", func(n string) bool { _, ok := s.hosts[n]; return ok }, &r.Hosts},
		{"hostgroup", func(string) bool { return false }, &r.HostGroups},
		{"service", func(string) bool { return false }, &r.Services},
		{"idoverrideuser", func(string) bool { return false }, nil},
		{"sysaccount", func(string) bool { return false }, nil},
	} {
		failed[k.opt] = [][]string{}
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
		"result":    renderRole(r, cn, true, flag(c, "all")),
		"completed": completed,
		"failed":    map[string]any{"member": failed},
	}, nil
}

func init() {
	builtins["role_show"] = func(s *Server, c Call) (any, *ipa.IpaError) { return rbacShow("role", s.roles, renderRole)(s, c) }
	builtins["privilege_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return rbacShow("privilege", s.privs, renderPrivilege)(s, c)
	}
	builtins["permission_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return rbacShow("permission", s.perms, renderPermission)(s, c)
	}
	builtins["role_find"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return rbacFind(s.roles, func(r *ipa.Role) string { return r.Description }, func(*ipa.Role) string { return "" }, renderRole)(s, c)
	}
	builtins["privilege_find"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return rbacFind(s.privs, func(p *ipa.Privilege) string { return p.Description }, func(*ipa.Privilege) string { return "" }, renderPrivilege)(s, c)
	}
	builtins["permission_find"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return rbacFind(s.perms, func(*ipa.Permission) string { return "" }, func(p *ipa.Permission) string { return p.Type }, renderPermission)(s, c)
	}
	builtins["role_add"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		return ruleAdd("role", s.roles, c, func(c Call) *ipa.Role { return &ipa.Role{Description: str(c.Options["description"])} }, renderRole)
	}
	builtins["role_del"] = func(s *Server, c Call) (any, *ipa.IpaError) { return ruleDel("role", s.roles, c) }
	builtins["role_add_member"] = roleAddMember
}

// Role returns a copy of role cn, with Name set to cn.
func (s *Server) Role(cn string) (ipa.Role, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[cn]
	if !ok {
		return ipa.Role{}, false
	}
	out := cloneRole(*r)
	out.Name = cn
	return *out, true
}

// Privilege returns a copy of privilege cn, with Name set to cn.
func (s *Server) Privilege(cn string) (ipa.Privilege, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.privs[cn]
	if !ok {
		return ipa.Privilege{}, false
	}
	out := *p
	out.Name, out.Permissions, out.Roles = cn, cloneStrs(p.Permissions), cloneStrs(p.Roles)
	return out, true
}

// Permission returns a copy of permission cn, with Name set to cn.
func (s *Server) Permission(cn string) (ipa.Permission, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.perms[cn]
	if !ok {
		return ipa.Permission{}, false
	}
	out := *p
	out.Name = cn
	out.Rights, out.Attrs, out.Filters, out.Privileges = cloneStrs(p.Rights), cloneStrs(p.Attrs), cloneStrs(p.Filters), cloneStrs(p.Privileges)
	return out, true
}
