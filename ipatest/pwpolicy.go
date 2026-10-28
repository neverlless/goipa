// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"
	"unicode"

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
// the name of a group. MaxLife and MinLife are rendered in whole days and
// hours; a sub-unit part is truncated.
func (s *Server) SetPwPolicy(cn string, p PwPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pwpol[cn] = p
}

// PwPolicy returns password policy cn.
func (s *Server) PwPolicy(cn string) (PwPolicy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pwpol[cn]
	return p, ok
}

func (p PwPolicy) render(cn string, withPriority bool) map[string]any {
	out := map[string]any{"cn": []string{cn}}
	set := func(k string, v int, always bool) {
		if v != 0 || always {
			out[k] = []string{strconv.Itoa(v)}
		}
	}
	// A group policy holds only what pwpolicy_add or SetPwPolicy set; zero
	// stands for never set.
	global := cn == globalPolicy
	if !global && withPriority {
		set("cospriority", p.Priority, false)
	}
	set("krbmaxpwdlife", int(p.MaxLife/(24*time.Hour)), global)
	set("krbminpwdlife", int(p.MinLife/time.Hour), global)
	set("krbpwdhistorylength", p.HistoryLength, global)
	set("krbpwdmindiffchars", p.MinClasses, global)
	set("krbpwdminlength", p.MinLength, global)
	set("krbpwdmaxfailure", p.MaxFailures, global)
	set("krbpwdfailurecountinterval", int(p.FailureInterval/time.Second), global)
	set("krbpwdlockoutduration", int(p.LockoutDuration/time.Second), global)
	set("ipapwdmaxrepeat", p.MaxRepeat, false)
	set("ipapwdmaxsequence", p.MaxSequence, false)
	set("passwordgracelimit", p.GraceLimit, false)
	for k, v := range map[string]int{"ipapwddcredit": p.DigitCredit, "ipapwducredit": p.UpperCredit,
		"ipapwdlcredit": p.LowerCredit, "ipapwdocredit": p.OtherCredit} {
		set(k, v, global)
	}
	for k, v := range map[string]bool{"ipapwddictcheck": p.DictCheck, "ipapwdusercheck": p.UserCheck} {
		if v || global {
			out[k] = []string{map[bool]string{true: "TRUE", false: "FALSE"}[v]}
		}
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

// setPassword stores pw. Q3: a password set by someone else is expired. The
// history keeps the newest passwords of the user's policy, current included
// (Q182); a password set while the policy keeps none leaves no entry.
func (s *Server) setPassword(uid string, r *userRec, pw string, self bool) {
	r.Password = pw
	if self {
		r.PasswdExpire, r.pwChanged = expiredNow().Add(pwdMaxLife), time.Now()
	} else {
		r.PasswdExpire = expiredNow()
	}
	if n := s.effectivePolicy(uid).HistoryLength; n > 0 {
		r.pwHistory = append(r.pwHistory, pw)
		r.pwHistory = r.pwHistory[max(0, len(r.pwHistory)-n):]
	}
}

func (s *Server) effectivePolicy(uid string) PwPolicy {
	cn, _ := s.userPolicy(uid)
	return s.pwpol[cn]
}

// pwViolation checks pw against the policy effective for uid (Q180) and
// returns FreeIPA's message, or "" if pw is acceptable. Only the user's own
// change is checked for length, classes and minimum lifetime; a change made by
// someone else is checked against the history alone (Q183).
func (s *Server) pwViolation(uid string, r *userRec, pw string, self bool) string {
	p := s.effectivePolicy(uid)
	const prefix = "Constraint violation: "
	if self {
		if p.MinLife > 0 && !r.pwChanged.IsZero() && (r.PasswdExpire.IsZero() || r.PasswdExpire.After(time.Now())) && time.Since(r.pwChanged) < p.MinLife {
			return prefix + "Too soon to change password"
		}
		if p.MinClasses > 0 && !enoughClasses(pw, p.MinClasses) { // Q181
			return prefix + "Password is too simple"
		}
		if len(pw) < p.MinLength {
			return prefix + "Password is too short"
		}
	}
	if n := p.HistoryLength; n > 0 && slices.Contains(r.pwHistory[max(0, len(r.pwHistory)-n):], pw) {
		return prefix + "Password reuse not permitted"
	}
	return ""
}

// enoughClasses implements Q181: at least min of lower, upper, digit and other,
// and more than min different characters.
func enoughClasses(pw string, min int) bool {
	var lower, upper, digit, other bool
	seen := map[rune]bool{}
	for _, c := range pw {
		seen[c] = true
		switch {
		case unicode.IsLower(c):
			lower = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsDigit(c):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n >= min && len(seen) > min
}

func init() {
	builtins["pwpolicy_show"] = func(s *Server, c Call) (any, *ipa.IpaError) {
		for _, k := range slices.Sorted(maps.Keys(c.Options)) {
			if !slices.Contains([]string{"all", "raw", "rights", "user", "version"}, k) {
				return nil, &ipa.IpaError{Code: ipa.CodeOption, Message: "Unknown option: " + k}
			}
		}
		cn := globalPolicy
		if len(c.Args) > 0 && c.Args[0] != "" {
			cn = c.Args[0]
		}
		uid := str(c.Options["user"])
		if !s.holds(c.User, "Password Policy Readers", "Password Policy Administrator") { // Q32: the ACI hides the entries
			name := "None"
			if len(c.Args) > 0 && c.Args[0] != "" {
				name = c.Args[0]
			}
			return nil, &ipa.IpaError{Code: ipa.CodeNotFound, Name: "NotFound", Message: name + ": password policy not found"}
		}
		if uid != "" {
			var ok bool
			if cn, ok = s.userPolicy(uid); !ok {
				return nil, notFound(uid, "user")
			}
		}
		p, ok := s.pwpol[cn]
		if !ok {
			return nil, notFound(cn, "password policy")
		}
		return entry(cn, p.render(cn, uid == ""), ""), nil
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
		p := PwPolicy{GraceLimit: -1} // passwordgracelimit is autofilled
		p.apply(c.Options)
		s.pwpol[cn] = p
		return entry(cn, p.render(cn, true), fmt.Sprintf("Added policy for %s", cn)), nil
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
