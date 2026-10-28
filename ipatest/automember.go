// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	ipa "github.com/neverlless/goipa"
)

const (
	inclusiveRE = "automemberinclusiveregex"
	exclusiveRE = "automemberexclusiveregex"
)

// amRule is an automember rule; conditions are stored as "key=regex".
type amRule struct {
	description          string
	inclusive, exclusive []string
}

func (r *amRule) list(attr string) *[]string {
	if attr == inclusiveRE {
		return &r.inclusive
	}
	return &r.exclusive
}

// amType reads the type option (Q110).
func amType(c Call) (string, *ipa.IpaError) {
	switch t := str(c.Options["type"]); t {
	case "group", "hostgroup":
		return t, nil
	case "":
		return "", required("type")
	}
	return "", &ipa.IpaError{Code: ipa.CodeValidation, Message: "invalid 'type': must be one of 'group', 'hostgroup'"}
}

func targetDN(typ, cn string) string {
	if typ == "hostgroup" {
		return "cn=" + cn + "," + hostGroupBaseDN
	}
	return "cn=" + cn + "," + groupBaseDN
}

// renderRule is a rule as automember_show prints it; dn is in show and find
// output even without all.
func renderRule(typ, cn string, r *amRule, all, dn bool) map[string]any {
	out := map[string]any{"cn": []string{cn}, "automembertargetgroup": []string{targetDN(typ, cn)}}
	if r.description != "" {
		out["description"] = []string{r.description}
	}
	if len(r.inclusive) > 0 {
		out[inclusiveRE] = slices.Clone(r.inclusive)
	}
	if len(r.exclusive) > 0 {
		out[exclusiveRE] = slices.Clone(r.exclusive)
	}
	if all {
		out["objectclass"] = []string{"top", "automemberregexrule"}
	}
	if all || dn {
		out["dn"] = "cn=" + cn + ",cn=" + typ + "," + automemberBaseDN
	}
	return out
}

// amName is the key of a rule: a host group rule is named after a host group.
func amName(typ, cn string) string {
	if typ == "hostgroup" {
		return hostGroupKey(cn)
	}
	return cn
}

func (s *Server) amRuleArg(c Call) (string, string, *amRule, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return "", "", nil, err
	}
	if len(c.Args) == 0 || c.Args[0] == "" {
		return "", "", nil, required("cn")
	}
	cn := amName(typ, c.Args[0])
	r := s.amRules[typ][cn]
	if r == nil {
		return "", "", nil, notFound(cn, "Automember rule")
	}
	return typ, cn, r, nil
}

func automemberShow(s *Server, c Call) (any, *ipa.IpaError) {
	typ, cn, r, err := s.amRuleArg(c)
	if err != nil {
		return nil, err
	}
	return entry(cn, renderRule(typ, cn, r, flag(c, "all"), true), ""), nil
}

func automemberFind(s *Server, c Call) (any, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return nil, err
	}
	needle := ""
	if len(c.Args) > 0 {
		needle = strings.ToLower(c.Args[0])
	}
	var cns []string
	for cn, r := range s.amRules[typ] {
		if needle != "" && !strings.Contains(strings.ToLower(cn), needle) && !strings.Contains(strings.ToLower(r.description), needle) {
			continue
		}
		if matches(c, "description", r.description) {
			cns = append(cns, cn)
		}
	}
	sort.Strings(cns)
	recs := make([]map[string]any, 0, len(cns))
	for _, cn := range cns {
		recs = append(recs, renderRule(typ, cn, s.amRules[typ][cn], flag(c, "all"), true))
	}
	out := list(recs)
	out["summary"] = fmt.Sprintf("%d rules matched", len(recs))
	return out, nil
}

func automemberAdd(s *Server, c Call) (any, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return nil, err
	}
	if len(c.Args) == 0 || c.Args[0] == "" {
		return nil, required("cn")
	}
	cn := amName(typ, c.Args[0])
	if err := s.refuse(c, false, noAdd("cn="+cn+",cn="+typ+","+automemberBaseDN)); err != nil { // Q170
		return nil, err
	}
	if s.amRules[typ][cn] != nil {
		return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: fmt.Sprintf("Automember rule with name %q already exists", cn)}
	}
	if !s.amTargetExists(typ, cn) {
		return nil, notFoundQuoted(cn, typ)
	}
	r := &amRule{description: str(c.Options["description"])}
	s.amRules[typ][cn] = r
	return entry(cn, renderRule(typ, cn, r, true, true), fmt.Sprintf("Added automember rule %q", cn)), nil
}

func (s *Server) amTargetExists(typ, cn string) bool {
	if typ == "hostgroup" {
		return s.hostgroups[cn] != nil
	}
	return s.groups[cn] != nil
}

// notFoundQuoted is FreeIPA's `<object> "<name>" not found`.
func notFoundQuoted(name, object string) *ipa.IpaError {
	return &ipa.IpaError{Code: ipa.CodeNotFound, Message: fmt.Sprintf("%s %q not found", object, name)}
}

// automemberDel deletes the rules up to the first missing one (Q114).
func automemberDel(s *Server, c Call) (any, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return nil, err
	}
	for _, cn := range c.Args {
		cn = amName(typ, cn)
		if s.amRules[typ][cn] == nil {
			return nil, notFound(cn, "Automember rule")
		}
		delete(s.amRules[typ], cn)
	}
	return map[string]any{
		"result":  map[string]any{"failed": []string{}},
		"value":   slices.Clone(c.Args),
		"summary": fmt.Sprintf("Deleted automember rule %q", strings.Join(c.Args, ",")),
	}, nil
}

// conditionCmd implements automember_{add,remove}_condition (Q111).
func conditionCmd(add bool) builtin {
	return func(s *Server, c Call) (any, *ipa.IpaError) {
		typ, err := amType(c)
		if err != nil {
			return nil, err
		}
		cn := ""
		if len(c.Args) > 0 {
			cn = amName(typ, c.Args[0])
		}
		r := s.amRules[typ][cn]
		if r == nil {
			return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Message: fmt.Sprintf("Auto member rule: %s not found!", cn)}
		}
		key := str(c.Options["key"])
		if key == "" {
			return nil, required("key")
		}
		completed := 0
		failed := map[string][]string{inclusiveRE: {}, exclusiveRE: {}}
		partial := map[string]any{}
		for _, attr := range []string{inclusiveRE, exclusiveRE} {
			vals := strs(c.Options[attr])
			l := r.list(attr)
			for _, v := range vals {
				cond := key + "=" + v
				switch has := slices.Contains(*l, cond); {
				case add && !has:
					*l = append(*l, cond)
					completed++
				case !add && has:
					*l = slices.DeleteFunc(*l, func(x string) bool { return x == cond })
					completed++
				case !add:
					failed[attr] = append(failed[attr], cond)
				}
			}
			if len(vals) > 0 {
				partial[attr] = slices.Clone(*l)
			}
		}
		res := renderRule(typ, cn, r, flag(c, "all"), false)
		if completed == 0 {
			res = partial
		}
		summary := fmt.Sprintf("Added condition(s) to %q", cn)
		if !add {
			summary = fmt.Sprintf("Removed condition(s) from %q", cn)
		}
		return map[string]any{
			"result":    res,
			"value":     cn,
			"failed":    map[string]any{"failed": failed},
			"completed": completed,
			"summary":   summary,
		}, nil
	}
}

func defaultEntry(s *Server, typ string, all bool) map[string]any {
	cn := strings.ToUpper(typ[:1]) + typ[1:]
	out := map[string]any{"cn": []string{cn}, "automemberdefaultgroup": "No default (fallback) group set"}
	if g := s.amDefs[typ]; g != "" {
		out["automemberdefaultgroup"] = []string{targetDN(typ, g)}
	}
	if all {
		out["dn"] = "cn=" + cn + "," + automemberBaseDN
	}
	return out
}

func defaultGroupShow(s *Server, c Call) (any, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return nil, err
	}
	return entry(typ, defaultEntry(s, typ, true), ""), nil
}

// defaultGroupSet is Q113: the group must exist, the current one is 4202.
func defaultGroupSet(s *Server, c Call) (any, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return nil, err
	}
	g := amName(typ, str(c.Options["automemberdefaultgroup"]))
	switch {
	case g == "":
		return nil, required("automemberdefaultgroup")
	case !s.amTargetExists(typ, g):
		return nil, notFoundQuoted(g, typ)
	case s.amDefs[typ] == g:
		return nil, &ipa.IpaError{Code: ipa.CodeEmptyModlist, Message: "no modifications to be performed"}
	}
	s.amDefs[typ] = g
	return entry(typ, defaultEntry(s, typ, false), fmt.Sprintf("Set default (fallback) group for automember %q", typ)), nil
}

func defaultGroupRemove(s *Server, c Call) (any, *ipa.IpaError) {
	typ, err := amType(c)
	if err != nil {
		return nil, err
	}
	if s.amDefs[typ] == "" {
		return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Message: "No default (fallback) group set"}
	}
	delete(s.amDefs, typ)
	return entry(typ, defaultEntry(s, typ, false), fmt.Sprintf("Removed default (fallback) group for automember %q", typ)), nil
}

// condMatches reports whether any "key=regex" condition matches the user.
// uid and the attributes User.attrVals knows are matched; others never are.
func condMatches(conds []string, uid string, u *User) bool {
	for _, cond := range conds {
		key, expr, _ := strings.Cut(cond, "=")
		key = strings.ToLower(key)
		vals, _ := u.attrVals(key)
		if key == "uid" {
			vals = []string{uid}
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			continue
		}
		if slices.ContainsFunc(vals, re.MatchString) {
			return true
		}
	}
	return false
}

// applyAutomember adds uid to the groups whose rules match it, or to the
// default group when none does (Q112). It needs s.mu held.
func (s *Server) applyAutomember(uid string) {
	r := s.users[uid]
	if r == nil {
		return
	}
	var hit []string
	for cn, rule := range s.amRules["group"] {
		if condMatches(rule.inclusive, uid, &r.User) && !condMatches(rule.exclusive, uid, &r.User) {
			hit = append(hit, cn)
		}
	}
	if len(hit) == 0 && s.amDefs["group"] != "" {
		hit = []string{s.amDefs["group"]}
	}
	sort.Strings(hit)
	for _, cn := range hit {
		if g := s.groups[cn]; g != nil && !slices.Contains(s.groupUsers(cn), uid) {
			g.Members = append(g.Members, uid)
		}
	}
}

func automemberRebuild(s *Server, c Call) (any, *ipa.IpaError) {
	n := 0
	typ := str(c.Options["type"])
	if typ == "" || typ == "group" {
		for _, uid := range slices.Sorted(maps.Keys(s.users)) {
			s.applyAutomember(uid)
			n++
		}
	}
	return map[string]any{
		"result":  map[string]any{},
		"value":   nil,
		"summary": fmt.Sprintf("Automember rebuild task finished. Processed (%d) entries in 0 seconds", n),
	}, nil
}

func init() {
	builtins["automember_show"] = automemberShow
	builtins["automember_find"] = automemberFind
	builtins["automember_add"] = automemberAdd
	builtins["automember_del"] = automemberDel
	builtins["automember_add_condition"] = conditionCmd(true)
	builtins["automember_remove_condition"] = conditionCmd(false)
	builtins["automember_default_group_show"] = defaultGroupShow
	builtins["automember_default_group_set"] = defaultGroupSet
	builtins["automember_default_group_remove"] = defaultGroupRemove
	builtins["automember_rebuild"] = automemberRebuild
}
