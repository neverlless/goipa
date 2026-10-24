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
