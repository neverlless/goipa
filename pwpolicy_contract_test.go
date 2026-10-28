// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
		_, err = b.rawAdmin().RPC("pwpolicy_show", nil, ipa.Options{"all": true, "no_members": false})
		if ierr := new(ipa.IpaError); !errors.As(err, &ierr) || ierr.Code != ipa.CodeOption {
			t.Errorf("no_members err = %v, want 3005 OptionError", err)
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
		if err != nil || p.Name != g || p.MinLength != 12 {
			t.Fatalf("UserPwPolicy(member) = %+v, %v", p, err)
		}
		if p, err := b.admin.PwPolicyShow(g); err != nil || p.Priority != 10 { // F2: not returned for the user form
			t.Errorf("PwPolicyShow(g) = %+v, %v", p, err)
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
		if !errors.Is(err, ipa.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

// Fresh passwords for the policy tests; goodPW is the one a new user starts with.
const (
	pwS1 = "Kj#82hd-Qm1x"
	pwS2 = "Zp$47tr+Wn5c"
	pwS3 = "Hb&93vf=Ly2d"
)

// pwFormResult posts the change_password form and returns the result and the
// policy message headers.
func pwFormResult(t *testing.T, b backend, uid, old, nw string) (string, string) {
	t.Helper()
	res := rawPost(t, b, "/ipa/session/change_password", url.Values{
		"user": {uid}, "old_password": {old}, "new_password": {nw}, "otp": {""},
	}, true)
	return res.Header.Get("X-IPA-Pwchange-Result"), res.Header.Get("X-IPA-Pwchange-Policy-Error")
}

// pwWant fails unless the form change old -> nw gets result and message.
func pwWant(t *testing.T, b backend, uid, old, nw, result, msg string) {
	t.Helper()
	if r, m := pwFormResult(t, b, uid, old, nw); r != result || m != msg {
		t.Errorf("%q -> %q: got %q %q, want %q %q", old, nw, r, m, result, msg)
	}
}

// pwWantRPC fails unless passwd by c gives 4203 with msg, or succeeds when msg is "".
func pwWantRPC(t *testing.T, c *ipa.Client, uid, cur, nw, msg string) {
	t.Helper()
	opts := ipa.Options{"password": nw}
	if cur != "" {
		opts["current_password"] = cur
	}
	_, err := c.RPC("passwd", []string{uid}, opts)
	var ie *ipa.IpaError
	switch {
	case msg == "" && err != nil:
		t.Errorf("passwd %q: %v", nw, err)
	case msg != "" && (!errors.As(err, &ie) || ie.Code != ipa.CodeDatabase || ie.Message != msg):
		t.Errorf("passwd %q: got %v, want 4203 %q", nw, err, msg)
	}
}

// groupPolicyUser returns a user of a group with policy opts.
func groupPolicyUser(t *testing.T, b backend, opts ipa.Options) string {
	t.Helper()
	uid := newUserWithPassword(t, b, goodPW)
	g := "gp" + randHex(t, 4)
	if _, err := b.admin.RPC("group_add", []string{g}, ipa.Options{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = b.admin.RPC("group_del", []string{g}, nil) })
	if _, err := b.admin.RPC("group_add_member", []string{g}, ipa.Options{"user": []string{uid}}); err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseInt(randHex(t, 2), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	opts["cospriority"] = 1000 + n // FreeIPA wants it unique
	if _, err := b.admin.RPC("pwpolicy_add", []string{g}, opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = b.admin.RPC("pwpolicy_del", []string{g}, nil) })
	return uid
}

// TestContractPasswordPolicyEffective pins Q180 and Q181.
func TestContractPasswordPolicyEffective(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := groupPolicyUser(t, b, ipa.Options{"krbpwdminlength": 12, "krbpwdmindiffchars": 3, "krbminpwdlife": 0})
		other := newUserWithPassword(t, b, goodPW)
		const short, simple = "Short-Pw1!", "Constraint violation: Password is too simple"
		const tooShort = "Constraint violation: Password is too short"

		// the global policy (8 characters) lets the 10-character password through
		pwWantRPC(t, b.admin, other, "", pwS1, "") // expired, so no minimum lifetime in the way
		if err := b.client().SetPassword(other, pwS1, short, ""); err != nil {
			t.Errorf("global policy: %v", err)
		}
		wantIs(t, b.client().SetPassword(uid, goodPW, short, ""), ipa.ErrPasswordPolicy)
		pwWant(t, b, uid, goodPW, short, "policy-error", tooShort)
		pwWant(t, b, uid, goodPW, "abcdefghijkl", "policy-error", simple)
		pwWant(t, b, uid, goodPW, "abcDefghijkl", "policy-error", simple)
		pwWant(t, b, uid, goodPW, "aaaDaaaa1aaa", "policy-error", simple) // Q181: three different characters
		pwWant(t, b, uid, goodPW, "abcdefghiJ1", "policy-error", tooShort)

		// Q180: the same limits apply to the passwd command
		pwWantRPC(t, mustLogin(t, b, uid, goodPW), uid, goodPW, short, tooShort)
		pwWantRPC(t, mustLogin(t, b, uid, goodPW), uid, goodPW, "abcdefghijkl", simple)

		// an admin sets whatever the length and classes (Q183)
		pwWantRPC(t, b.admin, uid, "", short, "")
		pwWant(t, b, uid, short, pwS1, "ok", "")
	})
}

// TestContractPasswordHistory pins Q182.
func TestContractPasswordHistory(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := groupPolicyUser(t, b, ipa.Options{"krbpwdhistorylength": 2, "krbminpwdlife": 0})
		const reuse = "Constraint violation: Password reuse not permitted"
		// the history sorts by second, so the changes need distinct seconds
		for i, pw := range []string{pwS1, pwS2, pwS3} {
			if i > 0 {
				time.Sleep(1100 * time.Millisecond)
			}
			prev := []string{goodPW, pwS1, pwS2}[i]
			pwWant(t, b, uid, prev, pw, "ok", "")
		}
		time.Sleep(1100 * time.Millisecond)
		pwWant(t, b, uid, pwS3, pwS3, "policy-error", reuse)
		pwWant(t, b, uid, pwS3, pwS2, "policy-error", reuse)
		pwWantRPC(t, b.admin, uid, "", pwS2, reuse)
		pwWantRPC(t, b.admin, uid, "", pwS1, "") // the third newest is free again
	})
}

// TestContractPasswordMinLife pins Q183.
func TestContractPasswordMinLife(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, goodPW) // just changed by its owner
		const soon = "Constraint violation: Too soon to change password"
		pwWant(t, b, uid, goodPW, pwS1, "policy-error", soon)
		pwWantRPC(t, mustLogin(t, b, uid, goodPW), uid, goodPW, pwS1, soon)

		pwWantRPC(t, b.admin, uid, "", pwS1, "") // expired, so the owner may change it
		pwWant(t, b, uid, pwS1, pwS2, "ok", "")
		pwWant(t, b, uid, pwS2, pwS3, "policy-error", soon)
	})
}

// TestContractPasswordCheckOrder pins Q181: the minimum lifetime is checked
// first, and a password that is both short and too simple gets the message the
// release checks first.
func TestContractPasswordCheckOrder(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := groupPolicyUser(t, b, ipa.Options{"krbpwdminlength": 12, "krbpwdmindiffchars": 3, "krbminpwdlife": 1})
		pwWantRPC(t, b.admin, uid, "", pwS1, "")
		pwWant(t, b, uid, pwS1, pwS2, "ok", "")
		pwWant(t, b, uid, pwS2, "abcdefghi", "policy-error", "Constraint violation: Too soon to change password")

		uid = groupPolicyUser(t, b, ipa.Options{"krbpwdminlength": 12, "krbpwdmindiffchars": 3, "krbminpwdlife": 0})
		res, err := b.admin.Ping()
		if err != nil {
			t.Fatal(err)
		}
		var x, y int
		if _, err := fmt.Sscanf(res.Version, "%d.%d", &x, &y); err != nil {
			t.Fatalf("server version %q: %v", res.Version, err)
		}
		want := "Constraint violation: Password is too simple"
		if x == 4 && y < 13 {
			want = "Constraint violation: Password is too short"
		}
		pwWant(t, b, uid, goodPW, "abcdefghi", "policy-error", want)
	})
}
