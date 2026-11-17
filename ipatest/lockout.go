// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"fmt"
	"strconv"
	"time"

	ipa "github.com/neverlless/goipa"
)

// userStatus implements user_status, Q31.
func userStatus(s *Server, c Call) (any, *ipa.IpaError) {
	uid, r, err := s.userArg(c)
	if err != nil {
		return nil, err
	}
	// The real server decodes the stored time into a datetime; "N/A" is unset.
	when := func(t time.Time) any {
		if t.IsZero() {
			return []string{"N/A"}
		}
		return []map[string]string{{"__datetime__": t.UTC().Format(ipa.IpaDatetimeFormat)}}
	}
	var count any = "0"
	if r.FailedLogins != 0 {
		count = []string{strconv.Itoa(r.FailedLogins)}
	}
	rec := map[string]any{
		"dn":                    "uid=" + uid + "," + baseDN,
		"server":                serverFQDN,
		"now":                   time.Now().UTC().Format(time.RFC3339),
		"krblastsuccessfulauth": []string{"N/A"},
		"krblastfailedauth":     when(r.LastFailedLogin),
		"krbloginfailedcount":   count,
		"passwordgraceusertime": "0",
	}
	out := list([]map[string]any{rec})
	disabled := "False"
	if r.Locked {
		disabled = "True"
	}
	out["summary"] = "Account disabled: " + disabled
	return out, nil
}

// userUnlock implements user_unlock, Q31.
func userUnlock(s *Server, c Call) (any, *ipa.IpaError) {
	uid, r, err := s.userArg(c)
	if err != nil {
		return nil, err
	}
	r.FailedLogins = 0
	return map[string]any{"result": true, "value": uid, "summary": fmt.Sprintf("Unlocked account %q", uid)}, nil
}

func init() {
	builtins["user_status"] = userStatus
	builtins["user_unlock"] = userUnlock
}

// lockedOut reports whether the effective policy of uid refuses logins now:
// MaxFailures wrong passwords in a row, until LockoutDuration after the last
// one (0 = until user_unlock), Q190.
func (s *Server) lockedOut(uid string, u *userRec) bool {
	p := s.effectivePolicy(uid)
	if p.MaxFailures <= 0 || u.FailedLogins < p.MaxFailures {
		return false
	}
	return p.LockoutDuration == 0 || time.Since(u.LastFailedLogin) < p.LockoutDuration
}

// countFailure records a wrong password. After a lockout has ended the count
// stays at MaxFailures and the failure only renews the lockout, Q191. A count
// older than FailureInterval restarts at 1, Q194.
func (s *Server) countFailure(uid string, u *userRec) {
	p := s.effectivePolicy(uid)
	if p.MaxFailures > 0 && u.FailedLogins >= p.MaxFailures {
		u.LastFailedLogin = time.Now()
		return
	}
	if p.FailureInterval > 0 && time.Since(u.LastFailedLogin) > p.FailureInterval {
		u.FailedLogins = 0
	}
	u.FailedLogins++
	u.LastFailedLogin = time.Now()
}
