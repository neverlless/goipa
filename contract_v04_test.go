// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// Contract tests for the FreeIPA behaviours v0.4 relies on (U1-U12 in the
// plan). Seeding goes through RPC and the admin client only, so they also run
// against a real server.

// newGroup adds a group through the admin session and deletes it afterwards.
func newGroup(t *testing.T, b backend) string {
	t.Helper()
	cn := "gg" + randHex(t, 4)
	if _, err := b.admin.GroupAdd(&ipa.Group{Name: cn}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.GroupDelete(cn) })
	return cn
}

func mustRPC(t *testing.T, c *ipa.Client, method string, args []string, opts ipa.Options) *ipa.Response {
	t.Helper()
	res, err := c.RPC(method, args, opts)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return res
}

// serverHost returns the FQDN of a host that exists on the backend: its own
// server host, or the one ipatest pre-seeds.
func serverHost(t *testing.T, b backend) string {
	t.Helper()
	hosts, err := b.admin.HostFind(ipa.Options{"sizelimit": 0})
	if err != nil || len(hosts) == 0 {
		t.Fatalf("HostFind: %v (%d hosts)", err, len(hosts))
	}
	own, _, _ := strings.Cut(b.host, ":")
	for _, h := range hosts {
		if h.FQDN == own {
			return own
		}
	}
	return hosts[0].FQDN
}

// U1
func TestContractFindHidesMembers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn, uid := newGroup(t, b), newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.GroupAddMember(cn, []string{uid}, nil); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			opts ipa.Options
			want bool
		}{
			{ipa.Options{"cn": cn}, false},
			{ipa.Options{"cn": cn, "all": true}, true},
			{ipa.Options{"cn": cn, "no_members": false}, true},
		} {
			res := mustRPC(t, b.admin, "group_find", []string{""}, tc.opts)
			rec := gjson.GetBytes(res.Result.Data, "0")
			if got := rec.Get("member_user").Exists(); got != tc.want {
				t.Errorf("group_find %v: member_user present = %v, want %v", tc.opts, got, tc.want)
			}
		}
	})
}

// U2
func TestContractUserFindFlattensNested(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		inner, outer, uid := newGroup(t, b), newGroup(t, b), newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.GroupAddMember(inner, []string{uid}, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.GroupAddMember(outer, nil, []string{inner}); err != nil {
			t.Fatal(err)
		}
		res := mustRPC(t, b.admin, "user_find", []string{""}, ipa.Options{"uid": uid, "all": true})
		rec := gjson.GetBytes(res.Result.Data, "0")
		groups := rec.Get("memberof_group").String()
		if !strings.Contains(groups, inner) || !strings.Contains(groups, outer) {
			t.Errorf("memberof_group = %s, want %s and %s", groups, inner, outer)
		}
		if rec.Get("memberofindirect_group").Exists() {
			t.Errorf("user_find returned memberofindirect_group: %s", rec.Get("memberofindirect_group"))
		}
	})
}

// U3
func TestContractMemberFailedShape(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn, uid := newGroup(t, b), newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.GroupAddMember(cn, []string{uid}, nil); err != nil {
			t.Fatal(err)
		}
		res := mustRPC(t, b.admin, "group_add_member", []string{cn},
			ipa.Options{"user": []string{uid}, "group": []string{"nosuchgroup" + randHex(t, 3)}})
		failed := gjson.ParseBytes(res.Result.Failed)
		if msg := failed.Get("member.user.0.1").String(); !strings.Contains(strings.ToLower(msg), "already") {
			t.Errorf("member.user = %s, want an already-a-member message", failed.Get("member.user"))
		}
		if !failed.Get("member.group.0.0").Exists() {
			t.Errorf("no member.group entry in %s", failed.Raw)
		}
	})
}

// U3
func TestContractMemberManagerFailedShape(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newGroup(t, b)
		res := mustRPC(t, b.admin, "group_add_member_manager", []string{cn},
			ipa.Options{"user": []string{"nosuchuser" + randHex(t, 3)}})
		if f := gjson.ParseBytes(res.Result.Failed); !f.Get("membermanager.user.0.0").Exists() {
			t.Errorf("no membermanager.user entry in %s", f.Raw)
		}
	})
}

// U3, U12
func TestContractMemberDeniedInFailed(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn, target := newGroup(t, b), newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: target, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		plain := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		res := mustRPC(t, plain, "group_add_member", []string{cn}, ipa.Options{"user": []string{target}})
		if f := gjson.ParseBytes(res.Result.Failed); !f.Get("member.user.0.0").Exists() {
			t.Errorf("denied add not reported in failed: %s", f.Raw)
		}
		_, err := plain.GroupAddMember(cn, []string{target}, nil)
		var me *ipa.MemberError
		if !errors.As(err, &me) {
			t.Fatalf("GroupAddMember by a plain user: got %v, want *MemberError", err)
		}
	})
}

// U4
func TestContractAddressNeedsAll(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		mustRPC(t, b.admin, "user_add", []string{uid}, ipa.Options{
			"givenname": "Go", "sn": "Test", "street": "1 Main St", "l": "Town", "st": "ST",
			"postalcode": "12345", "preferredlanguage": "en",
		})
		attrs := []string{"street", "l", "st", "postalcode", "preferredlanguage"}
		plain := gjson.ParseBytes(mustRPC(t, b.admin, "user_show", []string{uid}, nil).Result.Data)
		full := gjson.ParseBytes(mustRPC(t, b.admin, "user_show", []string{uid}, ipa.Options{"all": true}).Result.Data)
		for _, a := range attrs {
			if plain.Get(a).Exists() {
				t.Errorf("%s returned without all", a)
			}
			if !full.Get(a).Exists() {
				t.Errorf("%s missing with all", a)
			}
		}
		u, err := b.admin.UserShow(uid)
		if err != nil {
			t.Fatal(err)
		}
		if u.Street != "1 Main St" || u.City != "Town" || u.State != "ST" || u.PostalCode != "12345" || u.PreferredLanguage != "en" {
			t.Errorf("UserShow address fields: %+v", u)
		}
	})
}

// U5
func TestContractUserModMailReplaces(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		a, c := uid+"@example.com", uid+"b@example.com"
		mustRPC(t, b.admin, "user_add", []string{uid}, ipa.Options{"givenname": "Go", "sn": "Test", "mail": []string{a, c}})
		mails := func() string {
			return gjson.GetBytes(mustRPC(t, b.admin, "user_show", []string{uid}, nil).Result.Data, "mail").Raw
		}
		mustRPC(t, b.admin, "user_mod", []string{uid}, ipa.Options{"mail": a})
		if got := gjson.Parse(mails()).Array(); len(got) != 1 || got[0].String() != a {
			t.Errorf("mail=a left %s, want [a]", mails())
		}
		mustRPC(t, b.admin, "user_mod", []string{uid}, ipa.Options{"mail": []string{a, c}})
		if got := gjson.Parse(mails()).Array(); len(got) != 2 {
			t.Errorf("mail=[a,b] left %s, want both", mails())
		}
	})
}

// U6
func TestContractRandomPasswordScalar(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		mustRPC(t, b.admin, "user_add", []string{uid}, ipa.Options{"givenname": "Go", "sn": "Test"})
		res := mustRPC(t, b.admin, "user_mod", []string{uid}, ipa.Options{"random": true})
		if got := gjson.GetBytes(res.Result.Data, "randompassword"); got.Type != gjson.String {
			t.Fatalf("server %s: randompassword is %s, want a string", res.Version, got.Raw)
		}
	})
}

// U7
func TestContractChangePasswordEmptyOTP(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		for name, otp := range map[string]url.Values{
			"empty":  {"otp": {""}},
			"absent": {},
		} {
			uid := newUserWithPassword(t, b, goodPW)
			form := url.Values{"user": {uid}, "old_password": {goodPW}, "new_password": {"Another-Passw0rd-2"}}
			for k, v := range otp {
				form[k] = v
			}
			res := rawPost(t, b, "/ipa/session/change_password", form, true)
			if got := res.Header.Get("X-IPA-Pwchange-Result"); got != "ok" {
				t.Errorf("otp %s: X-IPA-Pwchange-Result = %q, want ok", name, got)
			}
		}
	})
}

// U8, U9
func TestContractGroupAddPosixFlags(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		for _, tc := range []struct {
			name            string
			opts            ipa.Options
			posix, external bool
		}{
			{"default", ipa.Options{}, true, false},
			{"nonposix", ipa.Options{"nonposix": true}, false, false},
			{"external", ipa.Options{"external": true}, false, true},
		} {
			cn := "gg" + randHex(t, 4)
			tc.opts["all"] = true
			mustRPC(t, b.admin, "group_add", []string{cn}, tc.opts)
			t.Cleanup(func() { _ = b.admin.GroupDelete(cn) })
			rec := gjson.GetBytes(mustRPC(t, b.admin, "group_show", []string{cn}, ipa.Options{"all": true}).Result.Data, "@this")
			classes := rec.Get("objectclass").String()
			if has := strings.Contains(classes, `"posixgroup"`); has != tc.posix {
				t.Errorf("%s: posixgroup in %s = %v, want %v", tc.name, classes, has, tc.posix)
			}
			if has := strings.Contains(classes, `"ipaexternalgroup"`); has != tc.external {
				t.Errorf("%s: ipaexternalgroup in %s = %v, want %v", tc.name, classes, has, tc.external)
			}
			if has := rec.Get("gidnumber").Exists(); has != tc.posix {
				t.Errorf("%s: gidnumber present = %v, want %v", tc.name, has, tc.posix)
			}
			g, err := b.admin.GroupShow(cn)
			if err != nil {
				t.Fatal(err)
			}
			if g.NonPOSIX == tc.posix || g.External != tc.external {
				t.Errorf("%s: GroupShow NonPOSIX=%v External=%v", tc.name, g.NonPOSIX, g.External)
			}
		}
	})
}

// U10
func TestContractGroupDelShape(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newGroup(t, b)
		res := mustRPC(t, b.admin, "group_del", []string{cn}, ipa.Options{"continue": false})
		if f := gjson.GetBytes(res.Result.Data, "failed"); !f.IsArray() || len(f.Array()) != 0 {
			t.Errorf("result.failed = %s, want []", f.Raw)
		}
		if v, ok := res.Result.Value.([]any); !ok || len(v) != 1 || v[0] != cn {
			t.Errorf("value = %v, want [%s]", res.Result.Value, cn)
		}
	})
}

// U11
func TestContractHostShape(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := serverHost(t, b)
		rec := gjson.GetBytes(mustRPC(t, b.admin, "host_show", []string{fqdn}, ipa.Options{"all": true}).Result.Data, "@this")
		for _, k := range []string{"has_keytab", "has_password"} {
			if v := rec.Get(k); v.Type != gjson.True && v.Type != gjson.False {
				t.Errorf("%s = %s, want a JSON bool", k, v.Raw)
			}
		}
		// ipatest does not model hostgroup commands; on a real server this
		// pins memberof_hostgroup with all.
		hg := "hg" + randHex(t, 4)
		if _, err := b.admin.RPC("hostgroup_add", []string{hg}, nil); err != nil {
			t.Logf("memberof_hostgroup not checked: hostgroup_add: %v", err)
			return
		}
		t.Cleanup(func() { _, _ = b.admin.RPC("hostgroup_del", []string{hg}, nil) })
		mustRPC(t, b.admin, "hostgroup_add_member", []string{hg}, ipa.Options{"host": []string{fqdn}})
		rec = gjson.GetBytes(mustRPC(t, b.admin, "host_show", []string{fqdn}, ipa.Options{"all": true}).Result.Data, "@this")
		if !strings.Contains(rec.Get("memberof_hostgroup").String(), hg) {
			t.Errorf("memberof_hostgroup = %s, want %s", rec.Get("memberof_hostgroup"), hg)
		}
	})
}

// U12
func TestContractPlainUserReads(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn, fqdn := newGroup(t, b), serverHost(t, b)
		plain := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		if _, err := plain.GroupShow(cn); err != nil {
			t.Errorf("GroupShow as a plain user: %v", err)
		}
		if _, err := plain.HostShow(fqdn); err != nil {
			t.Errorf("HostShow as a plain user: %v", err)
		}
	})
}
