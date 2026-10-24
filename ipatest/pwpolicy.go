// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	ipa "github.com/neverlless/goipa"
)

const globalPolicy = "global_policy"

// PwPolicy is a password policy of the fake server. The durations are
// rendered in the units FreeIPA uses on the wire: days for MaxLife, hours for
// MinLife, seconds for the rest.
type PwPolicy struct {
	Priority                                           int // cospriority; group policies only
	MaxLife, MinLife, FailureInterval, LockoutDuration time.Duration
	HistoryLength, MinClasses, MinLength               int
	MaxFailures, MaxRepeat, MaxSequence, GraceLimit    int
	DictCheck, UserCheck                               bool
	DigitCredit, UpperCredit, LowerCredit, OtherCredit int
}

func seedPwPolicies() map[string]PwPolicy {
	return map[string]PwPolicy{globalPolicy: {
		MaxLife: 90 * 24 * time.Hour, MinLife: time.Hour, MinLength: 8, MaxFailures: 6,
		FailureInterval: 60 * time.Second, LockoutDuration: 600 * time.Second, GraceLimit: -1,
	}}
}

// SetPwPolicy creates or replaces the password policy cn: "global_policy" or
// the name of a group.
func (s *Server) SetPwPolicy(cn string, p PwPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pwpol[cn] = p
}

func (p PwPolicy) render(cn string) map[string]any {
	out := map[string]any{"cn": []string{cn}}
	set := func(k string, v int, always bool) {
		if v != 0 || always {
			out[k] = []string{strconv.Itoa(v)}
		}
	}
	set("cospriority", p.Priority, false)
	if cn == globalPolicy {
		delete(out, "cospriority")
	}
	set("krbmaxpwdlife", int(p.MaxLife/(24*time.Hour)), true)
	set("krbminpwdlife", int(p.MinLife/time.Hour), true)
	set("krbpwdhistorylength", p.HistoryLength, true)
	set("krbpwdmindiffchars", p.MinClasses, true)
	set("krbpwdminlength", p.MinLength, true)
	set("krbpwdmaxfailure", p.MaxFailures, true)
	set("krbpwdfailurecountinterval", int(p.FailureInterval/time.Second), true)
	set("krbpwdlockoutduration", int(p.LockoutDuration/time.Second), true)
	set("ipapwdmaxrepeat", p.MaxRepeat, false)
	set("ipapwdmaxsequence", p.MaxSequence, false)
	set("passwordgracelimit", p.GraceLimit, false)
	for k, v := range map[string]int{"ipapwddcredit": p.DigitCredit, "ipapwducredit": p.UpperCredit,
		"ipapwdlcredit": p.LowerCredit, "ipapwdocredit": p.OtherCredit} {
		set(k, v, true)
	}
	for k, v := range map[string]bool{"ipapwddictcheck": p.DictCheck, "ipapwdusercheck": p.UserCheck} {
		out[k] = []string{map[bool]string{true: "TRUE", false: "FALSE"}[v]}
	}
	return out
}

// apply sets the wire-named options of pwpolicy_add.
func (p *PwPolicy) apply(opts map[string]any) {
	num := func(k string) (int, bool) {
		v, ok := opts[k]
		if !ok {
			return 0, false
		}
		f, _ := strconv.ParseFloat(fmt.Sprint(v), 64) // JSON numbers arrive as float64, wire strings as lists
		if l, isList := v.([]any); isList && len(l) > 0 {
			f, _ = strconv.ParseFloat(fmt.Sprint(l[0]), 64)
		}
		return int(f), true
	}
	for k, dst := range map[string]*int{"cospriority": &p.Priority, "krbpwdhistorylength": &p.HistoryLength,
		"krbpwdmindiffchars": &p.MinClasses, "krbpwdminlength": &p.MinLength, "krbpwdmaxfailure": &p.MaxFailures,
		"ipapwdmaxrepeat": &p.MaxRepeat, "ipapwdmaxsequence": &p.MaxSequence, "passwordgracelimit": &p.GraceLimit,
		"ipapwddcredit": &p.DigitCredit, "ipapwducredit": &p.UpperCredit, "ipapwdlcredit": &p.LowerCredit,
		"ipapwdocredit": &p.OtherCredit} {
		if n, ok := num(k); ok {
			*dst = n
		}
	}
	for k, dst := range map[string]*time.Duration{"krbmaxpwdlife": &p.MaxLife, "krbminpwdlife": &p.MinLife,
		"krbpwdfailurecountinterval": &p.FailureInterval, "krbpwdlockoutduration": &p.LockoutDuration} {
		if n, ok := num(k); ok {
			unit := time.Second
			switch k {
			case "krbmaxpwdlife":
				unit = 24 * time.Hour
			case "krbminpwdlife":
				unit = time.Hour
			}
			*dst = time.Duration(n) * unit
		}
	}
	if v, ok := opts["ipapwddictcheck"]; ok {
		p.DictCheck = fmt.Sprint(v) == "true" || str(v) == "TRUE"
	}
	if v, ok := opts["ipapwdusercheck"]; ok {
		p.UserCheck = fmt.Sprint(v) == "true" || str(v) == "TRUE"
	}
}

// userPolicy is the group policy with the lowest cospriority among uid's
// groups, nested ones included, else the global policy.
func (s *Server) userPolicy(uid string) (string, bool) {
	u := s.users[uid]
	if u == nil {
		return "", false
	}
	direct := s.userGroups(uid, u)
	best := globalPolicy
	for _, cn := range append(slices.Clone(direct), s.ancestors(direct)...) {
		p, ok := s.pwpol[cn]
		if !ok {
			continue
		}
		if b := s.pwpol[best]; best == globalPolicy || p.Priority < b.Priority || (p.Priority == b.Priority && cn < best) {
			best = cn
		}
	}
	return best, true
}

func init() {
	builtins["pwpolicy_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		cn := globalPolicy
		if len(c.Args) > 0 && c.Args[0] != "" {
			cn = c.Args[0]
		}
		if uid := str(c.Options["user"]); uid != "" {
			var ok bool
			if cn, ok = s.userPolicy(uid); !ok {
				return nil, notFound(uid, "user")
			}
		}
		p, ok := s.pwpol[cn]
		if !ok {
			return nil, notFound(cn, "password policy")
		}
		return entry(cn, p.render(cn), ""), nil
	}
	builtins["pwpolicy_add"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		if len(c.Args) == 0 || c.Args[0] == "" {
			return nil, required("group")
		}
		cn := c.Args[0]
		if s.groups[cn] == nil {
			return nil, notFound(cn, "group")
		}
		if _, ok := c.Options["cospriority"]; !ok {
			return nil, required("priority")
		}
		if _, ok := s.pwpol[cn]; ok {
			return nil, &ipa.IpaError{Code: ipa.CodeDuplicateEntry, Message: `password policy with name "` + cn + `" already exists`}
		}
		p := PwPolicy{}
		p.apply(c.Options)
		s.pwpol[cn] = p
		return entry(cn, p.render(cn), fmt.Sprintf("Added policy for %s", cn)), nil
	}
	builtins["pwpolicy_del"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		for _, cn := range c.Args {
			if _, ok := s.pwpol[cn]; !ok || cn == globalPolicy {
				return nil, notFound(cn, "password policy")
			}
		}
		for _, cn := range c.Args {
			delete(s.pwpol, cn)
		}
		return map[string]any{"result": map[string]any{"failed": []string{}}, "value": slices.Clone(c.Args),
			"summary": "Deleted policy"}, nil
	}
}
