// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// V4, V5
func TestContractUserStatusAndUnlock(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, "Secret123!")

		fresh, err := b.admin.RPC("user_status", []string{uid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if typ := gjson.GetBytes(fresh.Result.Data, "0.krbloginfailedcount").Type; typ != gjson.String { // V4
			t.Errorf("fresh krbloginfailedcount type = %v, want string", typ)
		}

		for range 2 {
			if err := b.client().RemoteLogin(uid, "wrong"); err == nil {
				t.Fatal("login with a wrong password succeeded")
			}
		}
		sts, err := b.admin.UserStatus(uid)
		if err != nil {
			t.Fatal(err)
		}
		if len(sts) == 0 {
			t.Fatal("no replicas")
		}
		maxFails := 0
		var worst *ipa.ReplicaStatus
		for _, s := range sts {
			if s.Err != "" {
				t.Errorf("replica %s: %s", s.Server, s.Err)
			}
			if s.FailedLogins > maxFails {
				maxFails, worst = s.FailedLogins, s
			}
			if s.Now.IsZero() {
				t.Errorf("replica %s: zero Now", s.Server)
			}
		}
		if maxFails < 2 {
			t.Errorf("max FailedLogins = %d, want >= 2", maxFails)
		}
		if worst != nil && worst.LastFailure.IsZero() {
			t.Errorf("replica %s: zero LastFailure after failed logins", worst.Server)
		}
		raw, err := b.admin.RPC("user_status", []string{uid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if typ := gjson.GetBytes(raw.Result.Data, "0.server").Type; typ != gjson.String { // V4
			t.Errorf("server type = %v, want string", typ)
		}

		if err := b.admin.UserUnlock(uid); err != nil { // V5
			t.Fatal(err)
		}
		sts, err = b.admin.UserStatus(uid)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sts {
			if s.FailedLogins != 0 {
				t.Errorf("replica %s: FailedLogins = %d after unlock", s.Server, s.FailedLogins)
			}
		}
	})
}

func TestContractUserStatus_NotFound(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		for name, err := range map[string]error{"UserStatus": func() error { _, err := b.admin.UserStatus(uid); return err }(), "UserUnlock": b.admin.UserUnlock(uid)} {
			var ie *ipa.IpaError
			if !errors.Is(err, ipa.ErrNotFound) || !errors.As(err, &ie) || ie != err {
				t.Errorf("%s: err = %v, want bare ErrNotFound", name, err)
			}
		}
	})
}
