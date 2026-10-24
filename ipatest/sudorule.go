// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"slices"
	"strings"

	ipa "github.com/neverlless/goipa"
)

// sudoSlot is one option of a sudo rule member call.
type sudoSlot struct {
	opt    string // user, group, host, hostgroup, sudocmd, sudocmdgroup
	list   func(*sudoRec) *[]string
	exists func(*Server, string) bool
	ext    string // attribute for names FreeIPA does not know (Q81); "" fails them
}

type sudoKind struct {
	attr  string // the key under failed
	slots []sudoSlot
}

func hasUser(s *Server, n string) bool    { return s.users[n] != nil }
func hasGroup(s *Server, n string) bool   { return s.groups[n] != nil }
func hasHost(s *Server, n string) bool    { _, ok := s.hosts[n]; return ok }
func hasSudoCmd(s *Server, n string) bool { _, ok := s.sudocmds[n]; return ok }
func noSuch(*Server, string) bool         { return false } // host and command groups are not modelled

var (
	sudoUsers = sudoKind{"memberuser", []sudoSlot{
		{"user", func(r *sudoRec) *[]string { return &r.Users }, hasUser, "externaluser"},
		{"group", func(r *sudoRec) *[]string { return &r.Groups }, hasGroup, "externaluser"},
	}}
	sudoHosts = sudoKind{"memberhost", []sudoSlot{
		{"host", func(r *sudoRec) *[]string { return &r.Hosts }, hasHost, "externalhost"},
		{"hostgroup", func(r *sudoRec) *[]string { return &r.HostGroups }, noSuch, ""},
	}}
	sudoAllow = sudoKind{"memberallowcmd", []sudoSlot{
		{"sudocmd", func(r *sudoRec) *[]string { return &r.AllowCommands }, hasSudoCmd, ""},
		{"sudocmdgroup", func(r *sudoRec) *[]string { return &r.AllowCommandGroups }, noSuch, ""},
	}}
	sudoDeny = sudoKind{"memberdenycmd", []sudoSlot{
		{"sudocmd", func(r *sudoRec) *[]string { return &r.DenyCommands }, hasSudoCmd, ""},
		{"sudocmdgroup", func(r *sudoRec) *[]string { return &r.DenyCommandGroups }, noSuch, ""},
	}}
	sudoRunAsUser = sudoKind{"ipasudorunas", []sudoSlot{
		{"user", func(r *sudoRec) *[]string { return &r.RunAsUsers }, hasUser, "ipasudorunasextuser"},
		{"group", func(r *sudoRec) *[]string { return &r.RunAsUserGroups }, hasGroup, "ipasudorunasextusergroup"},
	}}
	sudoRunAsGroup = sudoKind{"ipasudorunasgroup", []sudoSlot{
		{"group", func(r *sudoRec) *[]string { return &r.RunAsGroups }, hasGroup, "ipasudorunasextgroup"},
	}}
)

// sudoMember serves the sudorule_{add,remove}_* member calls in
// group_add_member's output shape; unknown names of the kinds FreeIPA keeps
// as external go to the external attribute and count as completed (Q81).
func sudoMember(add bool, k sudoKind) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, err := ruleName(c)
		if err != nil {
			return nil, err
		}
		r := s.sudo[cn]
		if r == nil {
			return nil, notFound(cn, "sudo rule")
		}
		failed := map[string][][]string{}
		completed := 0
		for _, sl := range k.slots {
			failed[sl.opt] = [][]string{}
			for _, n := range strs(c.Options[sl.opt]) {
				known := sl.exists(s, n)
				dst := sl.list(r)
				if !known && sl.ext != "" {
					n = strings.ToLower(n)
					dst = r.external(sl.ext)
				}
				msg := ""
				switch {
				case add && slices.Contains(*dst, n):
					msg = "This entry is already a member"
				case add && (known || sl.ext != ""):
					*dst = append(*dst, n)
				case slices.Contains(*dst, n):
					*dst = slices.DeleteFunc(*dst, func(m string) bool { return m == n })
				case !known:
					msg = "no such entry"
				default:
					msg = "This entry is not a member"
				}
				if msg != "" {
					failed[sl.opt] = append(failed[sl.opt], []string{n, msg})
				} else {
					completed++
				}
			}
		}
		return map[string]any{
			"result":    r.render(cn, !flag(c, "no_members"), flag(c, "all")),
			"completed": completed,
			"failed":    map[string]any{k.attr: failed},
		}, nil
	}
}

func (r *sudoRec) external(attr string) *[]string {
	if r.ext == nil {
		r.ext = map[string]*[]string{}
	}
	if r.ext[attr] == nil {
		r.ext[attr] = &[]string{}
	}
	return r.ext[attr]
}

func sudoRuleArg(s *Server, c Call) (string, *sudoRec, *ipa.IpaError) {
	cn, err := ruleName(c)
	if err != nil {
		return "", nil, err
	}
	r := s.sudo[cn]
	if r == nil {
		return "", nil, notFound(cn, "sudo rule")
	}
	return cn, r, nil
}

// sudoRuleFlag is sudorule_enable and sudorule_disable; the rule's current
// state does not matter (Q80).
func sudoRuleFlag(disabled bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		_, r, err := sudoRuleArg(s, c)
		if err != nil {
			return nil, err
		}
		r.Disabled = disabled
		return map[string]any{"result": true}, nil
	}
}

func init() {
	builtins["sudorule_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, r, err := sudoRuleArg(s, c)
		if err != nil {
			return nil, err
		}
		all := flag(c, "all")
		return entry(cn, r.render(cn, all || !flag(c, "no_members"), all), ""), nil
	}
	builtins["sudorule_enable"] = sudoRuleFlag(false)
	builtins["sudorule_disable"] = sudoRuleFlag(true)
	builtins["sudorule_remove_user"] = sudoMember(false, sudoUsers)
	builtins["sudorule_add_host"] = sudoMember(true, sudoHosts)
	builtins["sudorule_remove_host"] = sudoMember(false, sudoHosts)
	builtins["sudorule_add_allow_command"] = sudoMember(true, sudoAllow)
	builtins["sudorule_remove_allow_command"] = sudoMember(false, sudoAllow)
	builtins["sudorule_add_deny_command"] = sudoMember(true, sudoDeny)
	builtins["sudorule_remove_deny_command"] = sudoMember(false, sudoDeny)
	builtins["sudorule_add_runasuser"] = sudoMember(true, sudoRunAsUser)
	builtins["sudorule_remove_runasuser"] = sudoMember(false, sudoRunAsUser)
	builtins["sudorule_add_runasgroup"] = sudoMember(true, sudoRunAsGroup)
	builtins["sudorule_remove_runasgroup"] = sudoMember(false, sudoRunAsGroup)
	builtins["sudorule_remove_option"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		cn, r, err := sudoRuleArg(s, c)
		if err != nil {
			return nil, err
		}
		opts := strs(c.Options["ipasudoopt"])
		if len(opts) == 0 {
			return nil, required("ipasudoopt")
		}
		for _, o := range opts {
			if !slices.Contains(r.Options, o) {
				return nil, &ipa.IpaError{Code: ipa.CodeAttrValueNotFound, Message: fmt.Sprintf("ipasudoopt does not contain '%s'", o)} // Q82
			}
		}
		r.Options = slices.DeleteFunc(r.Options, func(o string) bool { return slices.Contains(opts, o) })
		return entry(cn, r.render(cn, !flag(c, "no_members"), flag(c, "all")), ""), nil
	}
	builtins["sudocmd_add"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		if len(c.Args) == 0 || c.Args[0] == "" {
			return nil, required("sudocmd")
		}
		cmd := c.Args[0]
		if _, ok := s.sudocmds[cmd]; ok {
			return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: `sudo command with name "` + cmd + `" already exists`}
		}
		desc := str(c.Options["description"])
		s.sudocmds[cmd] = desc
		out := map[string]any{"sudocmd": []string{cmd}}
		if desc != "" {
			out["description"] = []string{desc}
		}
		return entry(cmd, out, fmt.Sprintf("Added Sudo Command %q", cmd)), nil
	}
	builtins["sudocmd_del"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		for _, cmd := range c.Args {
			if _, ok := s.sudocmds[cmd]; !ok {
				return nil, notFound(cmd, "sudo command")
			}
		}
		for _, cmd := range c.Args {
			delete(s.sudocmds, cmd)
		}
		return map[string]any{
			"result":  map[string]any{"failed": []string{}},
			"value":   slices.Clone(c.Args),
			"summary": fmt.Sprintf("Deleted Sudo Command %q", strings.Join(c.Args, ",")),
		}, nil
	}
}
