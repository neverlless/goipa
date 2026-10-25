// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"slices"

	ipa "github.com/neverlless/goipa"
)

// hbacSvcs and hbacSvcGroups are FreeIPA's default HBAC services and service
// groups with their members (Q74, Q150); the fake cannot add others.
var (
	hbacSvcs = []string{"crond", "ftp", "gdm", "gdm-password", "gssftp", "kdm", "login", "proftpd",
		"pure-ftpd", "sshd", "su", "su-l", "sudo", "sudo-i", "systemd-user", "vsftpd"}
	hbacSvcGroups = map[string][]string{"Sudo": {"sudo", "sudo-i"}, "ftp": {"ftp", "gssftp", "proftpd", "pure-ftpd", "vsftpd"}}
)

func (s *Server) hbacRule(c Call) (string, *hbacRec, *ipa.IpaError) {
	cn, err := ruleName(c)
	if err != nil {
		return "", nil, err
	}
	r := s.hbac[cn]
	if r == nil {
		return "", nil, notFound(cn, "HBAC rule")
	}
	return cn, r, nil
}

func (s *Server) hbacRuleShow(c Call) (any, *ipa.IpaError) {
	cn, r, err := s.hbacRule(c)
	if err != nil {
		return nil, err
	}
	members := true
	if v, ok := c.Options["no_members"].(bool); ok {
		members = !v
	}
	return entry(cn, r.render(cn, members, flag(c, "all")), ""), nil
}

// hbacRuleToggle serves hbacrule_enable and hbacrule_disable (Q71).
func hbacRuleToggle(disable bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, r, err := s.hbacRule(c)
		if err != nil {
			return nil, err
		}
		r.Disabled = disable
		verb := "Enabled"
		if disable {
			verb = "Disabled"
		}
		return map[string]any{"result": true, "value": cn, "summary": fmt.Sprintf("%s HBAC rule %q", verb, cn)}, nil
	}
}

// hbacMembers serves hbacrule_{add,remove}_{user,host,service} (Q72, Q73).
func hbacMembers(part string, add bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, r, err := s.hbacRule(c)
		if err != nil {
			return nil, err
		}
		type list struct {
			opt   string
			known func(string) bool
			dst   *[]string
		}
		var cat string
		var lists [2]list
		switch part {
		case "user":
			cat = r.UserCategory
			lists = [2]list{
				{"user", func(n string) bool { return s.users[n] != nil }, &r.Users},
				{"group", func(n string) bool { return s.groups[n] != nil }, &r.Groups},
			}
		case "host":
			cat = r.HostCategory
			lists = [2]list{
				{"host", func(n string) bool { _, ok := s.hosts[n]; return ok }, &r.Hosts},
				{"hostgroup", func(n string) bool { return s.hostgroups[n] != nil }, &r.HostGroups},
			}
		default:
			cat = r.ServiceCategory
			lists = [2]list{
				{"hbacsvc", func(n string) bool { return slices.Contains(hbacSvcs, n) }, &r.Services},
				{"hbacsvcgroup", func(n string) bool { return hbacSvcGroups[n] != nil }, &r.ServiceGroups},
			}
		}
		if add && cat == "all" {
			return nil, &ipa.IpaError{Code: 4303, Name: "MutuallyExclusiveError",
				Message: part + "s cannot be added when " + part + " category='all'"}
		}
		failed := map[string][][]string{lists[0].opt: {}, lists[1].opt: {}}
		completed := 0
		for _, l := range lists {
			for _, n := range strs(c.Options[l.opt]) {
				if l.opt == "hostgroup" {
					n = hostGroupKey(n)
				}
				in := slices.Contains(*l.dst, n)
				switch {
				case add && in:
					failed[l.opt] = append(failed[l.opt], []string{n, "This entry is already a member"})
				case !add && !in:
					failed[l.opt] = append(failed[l.opt], []string{n, "This entry is not a member"})
				case !in && !l.known(n):
					failed[l.opt] = append(failed[l.opt], []string{n, "no such entry"})
				case add:
					*l.dst = append(*l.dst, n)
					completed++
				default:
					*l.dst = slices.DeleteFunc(*l.dst, func(m string) bool { return m == n })
					completed++
				}
			}
		}
		return map[string]any{
			"result":    r.render(cn, true, flag(c, "all")),
			"completed": completed,
			"failed":    map[string]any{"member" + part: failed},
		}, nil
	}
}

func init() {
	builtins["hbacrule_show"] = (*Server).hbacRuleShow
	builtins["hbacrule_enable"] = hbacRuleToggle(false)
	builtins["hbacrule_disable"] = hbacRuleToggle(true)
	builtins["hbacrule_remove_user"] = hbacMembers("user", false)
	builtins["hbacrule_add_host"] = hbacMembers("host", true)
	builtins["hbacrule_remove_host"] = hbacMembers("host", false)
	builtins["hbacrule_add_service"] = hbacMembers("service", true)
	builtins["hbacrule_remove_service"] = hbacMembers("service", false)
}
