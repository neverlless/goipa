// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
)

// TestContractUserManager pins Q185.
func TestContractUserManager(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		boss, uid := newUID(t, b), newUID(t, b)
		for _, u := range []string{boss, uid} {
			if _, err := b.admin.UserAdd(&ipa.User{Username: u, First: "Go", Last: "Test"}, false); err != nil {
				t.Fatal(err)
			}
		}
		wantErr := b.admin.SetManager(uid, newUID(t, b)) // never created
		wantIs(t, wantErr, ipa.ErrNotFound)
		var ie *ipa.IpaError
		if errors.As(wantErr, &ie) && !strings.HasPrefix(ie.Message, "manager ") {
			t.Errorf("message %q", ie.Message)
		}

		if err := b.admin.SetManager(uid, boss); err != nil {
			t.Fatal(err)
		}
		u, err := b.admin.UserShow(uid)
		if err != nil || u.Manager != boss {
			t.Fatalf("Manager = %q, %v; want %q", u.Manager, err, boss)
		}
		rawShow, _, err := ipa.Call[ipa.Entry](context.Background(), b.admin, "user_show", []string{uid}, ipa.Options{"all": true})
		if err != nil {
			t.Fatal(err)
		}
		if got := rawShow.Str("manager"); got != boss {
			t.Errorf("raw user_show manager = %q, want the uid %q", got, boss)
		}
		rawFind, _, err := ipa.Call[[]ipa.Entry](context.Background(), b.admin, "user_find", []string{}, ipa.Options{"uid": uid, "all": true})
		if err != nil || len(rawFind) != 1 {
			t.Fatal(rawFind, err)
		}
		if got := rawFind[0].Str("manager"); got != boss {
			t.Errorf("raw user_find manager = %q, want the uid %q", got, boss)
		}
		found, err := b.admin.UserFind(ipa.Options{"manager": boss})
		if err != nil || len(found) != 1 || found[0].Username != uid || found[0].Manager != boss {
			t.Fatalf("UserFind(manager) = %v, %v", found, err)
		}
		if err := b.admin.SetManager(uid, ""); err != nil {
			t.Fatal(err)
		}
		if u, err = b.admin.UserShow(uid); err != nil || u.Manager != "" {
			t.Fatalf("Manager after clear = %q, %v", u.Manager, err)
		}
	})
}

// TestContractPrincipalExpiration pins Q187 and Q188.
func TestContractPrincipalExpiration(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		future := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
		if err := b.admin.SetPrincipalExpiration(uid, future); err != nil {
			t.Fatal(err)
		}
		u, err := b.admin.UserShow(uid)
		if err != nil || !u.PrincipalExpire.Equal(future) {
			t.Fatalf("PrincipalExpire = %v, %v; want %v", u.PrincipalExpire, err, future)
		}
		if err := b.client().RemoteLogin(uid, goodPW); err != nil {
			t.Errorf("login before expiry: %v", err)
		}

		own := mustLogin(t, b, uid, goodPW)
		wantIs(t, own.SetPrincipalExpiration(uid, future.Add(time.Hour)), ipa.ErrACI) // Q188

		if err := b.admin.SetPrincipalExpiration(uid, time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		wantIs(t, b.client().RemoteLogin(uid, goodPW), ipa.ErrUnauthorized)
		if got := rawLogin(t, b, uid, goodPW).Header.Get("X-IPA-Rejection-Reason"); got != "krbprincipal-expired" {
			t.Errorf("rejection reason %q, want krbprincipal-expired", got)
		}

		before, _ := b.admin.UserShow(uid)
		reason := rawLogin(t, b, uid, "wrong").Header.Get("X-IPA-Rejection-Reason")
		afterU, _ := b.admin.UserShow(uid)
		if reason != "krbprincipal-expired" || afterU.LoginFailedCount != before.LoginFailedCount {
			t.Errorf("wrong password on an expired principal: reason %q, failed count %d -> %d; want krbprincipal-expired, unchanged", reason, before.LoginFailedCount, afterU.LoginFailedCount)
		}

		if err := b.admin.SetPrincipalExpiration(uid, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if u, err = b.admin.UserShow(uid); err != nil || !u.PrincipalExpire.IsZero() {
			t.Fatalf("PrincipalExpire after clear = %v, %v", u.PrincipalExpire, err)
		}
		if err := b.client().RemoteLogin(uid, goodPW); err != nil {
			t.Errorf("login after clear: %v", err)
		}
	})
}

// TestContractLoginCounters pins Q186.
func TestContractLoginCounters(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW)
		other := newUserWithPassword(t, b, goodPW)
		wantIs(t, b.client().RemoteLogin(uid, "wrong"), ipa.ErrInvalidPassword)
		u, err := b.admin.UserShow(uid)
		if err != nil || u.LoginFailedCount != 1 || u.LastLoginFail.IsZero() {
			t.Fatalf("admin view: count %d, fail %v, %v", u.LoginFailedCount, u.LastLoginFail, err)
		}
		plain := mustLogin(t, b, other, goodPW)
		pu, err := plain.UserShow(uid)
		if err != nil {
			t.Fatal(err)
		}
		if pu.LoginFailedCount != 0 || !pu.LastLoginFail.IsZero() {
			t.Errorf("plain user reads another's counters: %d, %v", pu.LoginFailedCount, pu.LastLoginFail)
		}
		wantIs(t, b.client().RemoteLogin(other, "wrong"), ipa.ErrInvalidPassword)
		ou, err := plain.UserShow(other)
		if err != nil || ou.LoginFailedCount != 0 || !ou.LastLoginFail.IsZero() {
			t.Errorf("plain user reads own counters: %d, %v, %v", ou.LoginFailedCount, ou.LastLoginFail, err)
		}
	})
}
