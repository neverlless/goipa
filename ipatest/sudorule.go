// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
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
	all   func(*sudoRec) bool // the category that refuses adds (Q152); nil for none
	what  string              // MutuallyExclusiveError's reason
}

func hasUser(s *Server, n string) bool      { return s.users[n] != nil }
func hasGroup(s *Server, n string) bool     { return s.groups[n] != nil }
func hasHost(s *Server, n string) bool      { _, ok := s.hosts[n]; return ok }
func hasHostGroup(s *Server, n string) bool { return s.hostgroups[n] != nil }
func hasSudoCmd(s *Server, n string) bool   { _, ok := s.sudocmds[n]; return ok }
func noSuch(*Server, string) bool           { return false } // command groups are not modelled

var (
	sudoUsers = sudoKind{"memberuser", []sudoSlot{
		{"user", func(r *sudoRec) *[]string { return &r.Users }, hasUser, "externaluser"},
		{"group", func(r *sudoRec) *[]string { return &r.Groups }, hasGroup, "externaluser"},
	}, func(r *sudoRec) bool { return r.UserCategory == "all" }, "users cannot be added when user category='all'"}
	sudoHosts = sudoKind{"memberhost", []sudoSlot{
		{"host", func(r *sudoRec) *[]string { return &r.Hosts }, hasHost, "externalhost"},
		{"hostgroup", func(r *sudoRec) *[]string { return &r.HostGroups }, hasHostGroup, ""},
	}, func(r *sudoRec) bool { return r.HostCategory == "all" }, "hosts cannot be added when host category='all'"}
	sudoAllow = sudoKind{"memberallowcmd", []sudoSlot{
		{"sudocmd", func(r *sudoRec) *[]string { return &r.AllowCommands }, hasSudoCmd, ""},
		{"sudocmdgroup", func(r *sudoRec) *[]string { return &r.AllowCommandGroups }, noSuch, ""},
	}, func(r *sudoRec) bool { return r.CmdCategory == "all" }, "commands cannot be added when command category='all'"}
	sudoDeny = sudoKind{"memberdenycmd", []sudoSlot{
		{"sudocmd", func(r *sudoRec) *[]string { return &r.DenyCommands }, hasSudoCmd, ""},
		{"sudocmdgroup", func(r *sudoRec) *[]string { return &r.DenyCommandGroups }, noSuch, ""},
	}, nil, ""}
	sudoRunAsUser = sudoKind{"ipasudorunas", []sudoSlot{
		{"user", func(r *sudoRec) *[]string { return &r.RunAsUsers }, hasUser, "ipasudorunasextuser"},
		{"group", func(r *sudoRec) *[]string { return &r.RunAsUserGroups }, hasGroup, "ipasudorunasextusergroup"},
	}, runAsAll, "users cannot be added when runAs user or runAs group category='all'"}
	sudoRunAsGroup = sudoKind{"ipasudorunasgroup", []sudoSlot{
		{"group", func(r *sudoRec) *[]string { return &r.RunAsGroups }, hasGroup, "ipasudorunasextgroup"},
	}, runAsAll, "users cannot be added when runAs user or runAs group category='all'"}
)

func runAsAll(r *sudoRec) bool { return r.RunAsUserCategory == "all" || r.RunAsGroupCategory == "all" }

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
		if add && k.all != nil && k.all(r) {
			return nil, &ipa.IpaError{Code: 4303, Name: "MutuallyExclusiveError", Message: k.what}
		}
		failed := map[string][][]string{}
		completed := 0
		for _, sl := range k.slots {
			failed[sl.opt] = [][]string{}
			for _, n := range strs(c.Options[sl.opt]) {
				if sl.opt == "hostgroup" {
					n = hostGroupKey(n)
				}
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
				case !add:
					msg = "This entry is not a member"
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

// sudoOpts reads ipasudoopt; 4.9 takes no list there (Q83).
func (s *Server) sudoOpts(c Call) ([]string, *ipa.IpaError) {
	v := c.Options["ipasudoopt"]
	if _, list := v.([]any); list && strings.HasPrefix(s.version, "4.9.") {
		return nil, &ipa.IpaError{Code: ipa.CodeConversion, Message: "invalid 'ipasudoopt': Only one value is allowed"}
	}
	opts := strs(v)
	if len(opts) == 0 {
		return nil, required("ipasudoopt")
	}
	return opts, nil
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

// sudoOrderTaken is Q151: order held by a rule other than self.
func (s *Server) sudoOrderTaken(order int, self string) *ipa.IpaError {
	for _, cn := range slices.Sorted(maps.Keys(s.sudo)) {
		if order != 0 && cn != self && s.sudo[cn].Order == order {
			return &ipa.IpaError{Code: ipa.CodeValidation,
				Message: fmt.Sprintf("invalid 'order': order must be a unique value (%d already used by %s)", order, cn)}
		}
	}
	return nil
}

// sudoOrder converts sudoorder as FreeIPA's Int parameter does (Q151).
func sudoOrder(c Call) (int, *ipa.IpaError) {
	v, ok := c.Options["sudoorder"]
	if !ok {
		return 0, nil
	}
	if f, ok := v.(float64); ok {
		return int(f), nil
	}
	n, err := strconv.Atoi(str(v))
	if err != nil {
		return 0, &ipa.IpaError{Code: ipa.CodeConversion, Message: "invalid 'sudoorder': must be an integer"}
	}
	return n, nil
}

// sudoRuleMod changes description and sudoorder only (Q151).
func sudoRuleMod(s *Server, c Call) (any, *ipa.IpaError) {
	cn, r, err := sudoRuleArg(s, c)
	if err != nil {
		return nil, err
	}
	for k := range c.Options {
		if !slices.Contains([]string{"all", "raw", "rights", "no_members", "version", "description", "sudoorder"}, k) {
			return nil, &ipa.IpaError{Code: ipa.CodeCommand, Message: "ipatest: sudorule_mod models description and sudoorder only, not " + k}
		}
	}
	desc, order := r.Description, r.Order
	if v, ok := c.Options["description"]; ok {
		desc = str(v)
	}
	if _, ok := c.Options["sudoorder"]; ok {
		if order, err = sudoOrder(c); err != nil {
			return nil, err
		}
		if order != r.Order {
			if err := s.sudoOrderTaken(order, cn); err != nil {
				return nil, err
			}
		}
	}
	if desc == r.Description && order == r.Order {
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	r.Description, r.Order = desc, order
	return entry(cn, r.render(cn, !flag(c, "no_members"), flag(c, "all")), fmt.Sprintf("Modified sudo rule %q", cn)), nil
}

func init() {
	builtins["sudorule_mod"] = sudoRuleMod
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
		opts, err := s.sudoOpts(c)
		if err != nil {
			return nil, err
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
