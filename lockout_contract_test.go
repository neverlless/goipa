// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

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

// newPolicyGroup creates a group holding uid with a policy of priority prio
// and the given lockout settings; both are deleted when the test ends.
func newPolicyGroup(t *testing.T, b backend, uid string, opts ipa.Options) {
	t.Helper()
	cn := "gp" + randHex(t, 4)
	if _, err := b.admin.GroupAdd(&ipa.Group{Name: cn}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.GroupDelete(cn) })
	if _, err := b.admin.GroupAddMember(cn, []string{uid}, nil); err != nil {
		t.Fatal(err)
	}
	// cospriority is unique per server; random so reruns and legs do not collide.
	prio, err := strconv.ParseInt(randHex(t, 2), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	opts["cospriority"] = 100 + prio
	if _, err := b.admin.RPC("pwpolicy_add", []string{cn}, opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = b.admin.RPC("pwpolicy_del", []string{cn}, nil) })
}

// TestContractPwPolicyFind pins Q192, Q193.
func TestContractPwPolicyFind(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		newPolicyGroup(t, b, uid, ipa.Options{"krbpwdmaxfailure": 2})
		ps, err := b.admin.PwPolicyFind(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(ps) < 2 {
			t.Fatalf("policies = %d, want global and the group's", len(ps))
		}
		for i := 1; i < len(ps)-1; i++ {
			if ps[i].Priority < ps[i-1].Priority {
				t.Errorf("%s (%d) after %s (%d): not ascending", ps[i].Name, ps[i].Priority, ps[i-1].Name, ps[i-1].Priority)
			}
		}
		if last := ps[len(ps)-1]; last.Name != "global_policy" || last.Priority != 0 || ps[0].Priority == 0 { // Q193
			t.Errorf("order %s..%s, want group policies first and global_policy last", ps[0].Name, last.Name)
		}
		plain := mustLogin(t, b, uid, goodPW)
		hidden, err := plain.PwPolicyFind(nil)
		if err != nil || len(hidden) != 0 { // Q192
			t.Errorf("plain user sees %d policies, err %v", len(hidden), err)
		}
	})
}

// TestContractLockoutGroupPolicy pins Q190, Q191, Q194 (Review Focus 4).
func TestContractLockoutGroupPolicy(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		newPolicyGroup(t, b, uid, ipa.Options{"krbpwdmaxfailure": 2, "krbpwdlockoutduration": 3, "krbpwdfailurecountinterval": 60})
		count := func() string {
			raw, err := b.admin.RPC("user_status", []string{uid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			return gjson.GetBytes(raw.Result.Data, "0.krbloginfailedcount").Array()[0].String() // scalar when 0, else a list (Q31)
		}
		for range 2 {
			wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
		}
		wantReason, wantErr := lockedLogin(t, b)
		wantIs(t, b.client().RemoteLogin(uid, goodPW), wantErr) // Q190
		if got := rawLogin(t, b, uid, goodPW).Header.Get("X-IPA-Rejection-Reason"); got != wantReason {
			t.Fatalf("rejection reason %q, want %s", got, wantReason)
		}
		if n := count(); n != "2" {
			t.Errorf("count while locked = %s, want 2", n)
		}
		time.Sleep(4 * time.Second)
		// Q191: a wrong password after the lockout is an ordinary invalid-password,
		// leaves the count at the maximum and starts the lockout again.
		wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
		wantIs(t, b.client().RemoteLogin(uid, goodPW), wantErr)
		if n := count(); n != "2" {
			t.Errorf("count after a failure past the lockout = %s, want 2", n)
		}
		time.Sleep(4 * time.Second)
		if err := b.client().RemoteLogin(uid, goodPW); err != nil {
			t.Errorf("right password after the lockout: %v", err)
		}
		if n := count(); n != "0" {
			t.Errorf("count after a good login = %s, want 0", n)
		}
		for range 2 {
			wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
		}
		wantIs(t, b.client().RemoteLogin(uid, goodPW), wantErr)
		if err := b.admin.UserUnlock(uid); err != nil {
			t.Fatal(err)
		}
		if err := b.client().RemoteLogin(uid, goodPW); err != nil {
			t.Errorf("right password after UserUnlock: %v", err)
		}
	})
}

// TestContractLockoutInterval pins Q194.
func TestContractLockoutInterval(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		newPolicyGroup(t, b, uid, ipa.Options{"krbpwdmaxfailure": 3, "krbpwdlockoutduration": 60, "krbpwdfailurecountinterval": 2})
		count := func() string {
			raw, err := b.admin.RPC("user_status", []string{uid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			return gjson.GetBytes(raw.Result.Data, "0.krbloginfailedcount").Array()[0].String() // scalar when 0, else a list (Q31)
		}
		for i, want := range []string{"1", "1", "2"} { // the second failure comes after the interval
			if i == 1 {
				time.Sleep(4 * time.Second)
			}
			wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
			if n := count(); n != want {
				t.Errorf("count after failure %d = %s, want %s", i+1, n, want)
			}
		}
	})
}
