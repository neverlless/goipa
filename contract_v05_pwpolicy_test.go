// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// V6
func TestContractPwPolicyGlobal(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		p, err := b.admin.PwPolicyShow("")
		if err != nil {
			t.Fatal(err)
		}
		if p.Name != "global_policy" || p.MaxLife != 90*24*time.Hour || p.MinLife != time.Hour || p.MinLength < 1 || p.MaxFailures != 6 {
			t.Errorf("policy = %+v", p)
		}
		raw, err := b.admin.RPC("pwpolicy_show", nil, ipa.Options{"all": true})
		if err != nil {
			t.Fatal(err)
		}
		if got := gjson.GetBytes(raw.Result.Data, "krbmaxpwdlife.0").String(); got != "90" {
			t.Errorf("krbmaxpwdlife = %q, want 90", got)
		}
		t.Logf("ipapwddictcheck raw: %s", gjson.GetBytes(raw.Result.Data, "ipapwddictcheck").Raw)
		if b.name == "ipatest" {
			if got := gjson.GetBytes(raw.Result.Data, "ipapwddictcheck").Raw; got != `["FALSE"]` {
				t.Errorf("ipatest ipapwddictcheck = %s, want [\"FALSE\"]", got)
			}
		}
	})
}

func TestContractUserPwPolicy(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid, other := newUID(t, b), newUID(t, b)
		for _, u := range []string{uid, other} {
			if _, err := b.admin.UserAdd(&ipa.User{Username: u, First: "Go", Last: "Test"}, false); err != nil {
				t.Fatal(err)
			}
		}
		g := "gp" + randHex(t, 4)
		if _, err := b.admin.RPC("group_add", []string{g}, ipa.Options{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = b.admin.RPC("group_del", []string{g}, nil) })
		if _, err := b.admin.RPC("group_add_member", []string{g}, ipa.Options{"user": []string{uid}}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.RPC("pwpolicy_add", []string{g}, ipa.Options{"cospriority": 10, "krbpwdminlength": 12}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = b.admin.RPC("pwpolicy_del", []string{g}, nil) })

		p, err := b.admin.UserPwPolicy(uid)
		if err != nil || p.Name != g || p.Priority != 10 || p.MinLength != 12 {
			t.Fatalf("UserPwPolicy(member) = %+v, %v", p, err)
		}
		p, err = b.admin.UserPwPolicy(other)
		if err != nil || p.Name != "global_policy" {
			t.Fatalf("UserPwPolicy(other) = %+v, %v", p, err)
		}
	})
}

// V7
func TestContractPwPolicyPlainUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, "Secret123!")
		c := b.client()
		if err := c.RemoteLogin(uid, "Secret123!"); err != nil {
			t.Fatal(err)
		}
		p, err := c.PwPolicyShow("")
		t.Logf("plain user reads global_policy: %+v, err = %v", p, err)
		if err != nil && !errors.Is(err, ipa.ErrACI) {
			t.Errorf("err = %v, want nil or ErrACI", err)
		}
	})
}
