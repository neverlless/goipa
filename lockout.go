// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// ReplicaStatus is one IPA master's view of a user's Kerberos login state
// (user_status).
type ReplicaStatus struct {
	// Server is the master; only the host part when it could not be queried
	// (then Err is set).
	Server string
	// Err is the reason the master could not be queried, "" when it answered.
	Err string
	// FailedLogins is krbloginfailedcount.
	FailedLogins int
	// LastSuccess and LastFailure are krblastsuccessfulauth and
	// krblastfailedauth, read from FreeIPA's {"__datetime__": ...} form or an
	// RFC 3339 string; zero for "N/A".
	LastSuccess, LastFailure time.Time
	// Now is the master's clock.
	Now time.Time
}

// scalarOrFirst reads a value FreeIPA returns as a scalar or a one-element
// list, depending on whether the attribute is set.
func scalarOrFirst(res gjson.Result, key string) string {
	v := res.Get(key)
	if v.IsArray() {
		return v.Get("0").String()
	}
	return v.String()
}

// parseTime reads a time in either form: FreeIPA's {"__datetime__": ...}
// (what real servers send for the Kerberos times), or an RFC 3339 string.
// "N/A" and anything else unparsable is the zero time.
func parseTime(res gjson.Result, key string) time.Time {
	v := res.Get(key)
	if v.IsArray() {
		v = v.Get("0")
	}
	if dt := v.Get("__datetime__"); dt.Exists() {
		return ParseDateTime(dt.String())
	}
	t, _ := time.Parse(time.RFC3339, v.String())
	return t
}

// UserStatus reports a user's failed logins with `user_status`; one entry per
// master, each master is queried live. Without the User Administrators
// privilege FreeIPA hides the counters (FailedLogins 0, zero times) instead of
// failing.
func (c *Client) UserStatus(username string) ([]*ReplicaStatus, error) {
	return c.UserStatusContext(context.Background(), username)
}

// UserStatusContext is like UserStatus but bounds the request with ctx.
func (c *Client) UserStatusContext(ctx context.Context, username string) ([]*ReplicaStatus, error) {
	if username == "" {
		return nil, errors.New("ipa: username is required")
	}
	res, err := c.rpc(ctx, "user_status", []string{username}, Options{"all": true})
	if err != nil {
		return nil, err
	}
	var out []*ReplicaStatus
	gjson.ParseBytes(res.Result.Data).ForEach(func(_, e gjson.Result) bool {
		rs := &ReplicaStatus{Server: scalarOrFirst(e, "server")}
		if host, reason, ok := strings.Cut(rs.Server, " failed: "); ok && !e.Get("now").Exists() {
			rs.Server, rs.Err = host, reason
		} else {
			rs.FailedLogins, _ = strconv.Atoi(scalarOrFirst(e, "krbloginfailedcount"))
			rs.LastSuccess = parseTime(e, "krblastsuccessfulauth")
			rs.LastFailure = parseTime(e, "krblastfailedauth")
			rs.Now = parseTime(e, "now")
		}
		out = append(out, rs)
		return true
	})
	return out, nil
}

// UserUnlock resets a user's failed login counter with `user_unlock`. It
// requires User Administrators (System: Unlock User). On FreeIPA 4.13 members
// of admins and trust admins cannot be unlocked through delegation (2100).
// It writes the local master; replication carries it.
func (c *Client) UserUnlock(username string) error {
	return c.UserUnlockContext(context.Background(), username)
}

// UserUnlockContext is like UserUnlock but bounds the request with ctx.
func (c *Client) UserUnlockContext(ctx context.Context, username string) error {
	if username == "" {
		return errors.New("ipa: username is required")
	}
	_, err := c.rpc(ctx, "user_unlock", []string{username}, nil)
	return err
}
