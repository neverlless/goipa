// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

func wantMessage(t *testing.T, what string, err error, code int, msg string) {
	t.Helper()
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != code || ie.Message != msg {
		t.Errorf("%s: err = %v, want %d %q", what, err, code, msg)
	}
}

// strSet is the strings of a gjson array, sorted.
func strSet(r gjson.Result) []string {
	var out []string
	for _, v := range r.Array() {
		out = append(out, v.String())
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string { slices.Sort(s); return s }

// TestContractHostDeleteServices pins Q146.
func TestContractHostDeleteServices(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		other, host := newService(t, b) // first: serverHost may pick any existing host
		_, domain, _ := strings.Cut(host, ".")
		fqdn := "goipa" + randHex(t, 4) + "." + domain
		mustRPC(t, b.admin, "host_add", []string{fqdn}, ipa.Options{"force": true})
		t.Cleanup(func() { _, _ = b.admin.RPC("host_del", []string{fqdn}, nil) })
		own := "HTTP/" + fqdn + "@" + b.realm
		if _, err := b.admin.ServiceAdd(own, true); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.ServiceAddHost(other, []string{fqdn}); err != nil {
			t.Fatal(err)
		}
		mustRPC(t, b.admin, "host_del", []string{fqdn}, nil)
		_, err := b.admin.ServiceShow(own)
		wantIs(t, err, ipa.ErrNotFound)
		svc, err := b.admin.ServiceShow(other)
		if err != nil || !slices.Equal(svc.ManagedBy, []string{host}) {
			t.Errorf("other service = %+v, %v", svc, err)
		}
	})
}

// TestContractHostGroupCycle pins Q140.
func TestContractHostGroupCycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		a, bb, c := newHostGroup(t, b), newHostGroup(t, b), newHostGroup(t, b)
		for _, m := range [][2]string{{a, bb}, {bb, a}, {bb, c}, {c, a}} {
			if _, err := b.admin.HostGroupAddMember(m[0], nil, []string{m[1]}); err != nil {
				t.Fatalf("add %s to %s: %v", m[1], m[0], err)
			}
		}
		show := func(cn string) gjson.Result {
			t.Helper()
			return gjson.ParseBytes(mustRPC(t, b.admin, "hostgroup_show", []string{cn}, nil).Result.Data)
		}
		for _, w := range []struct {
			cn                       string
			memberOf, indirect, ofIn []string
		}{
			{a, sorted(bb, c), sorted(a, c), nil},
			{c, []string{bb}, sorted(bb, c), []string{a}},
		} {
			g := show(w.cn)
			if got := strSet(g.Get("memberof_hostgroup")); !slices.Equal(got, w.memberOf) {
				t.Errorf("%s memberof_hostgroup = %v, want %v", w.cn, got, w.memberOf)
			}
			if got := strSet(g.Get("memberindirect_hostgroup")); !slices.Equal(got, w.indirect) {
				t.Errorf("%s memberindirect_hostgroup = %v, want %v", w.cn, got, w.indirect)
			}
			if got := strSet(g.Get("memberofindirect_hostgroup")); !slices.Equal(got, w.ofIn) {
				t.Errorf("%s memberofindirect_hostgroup = %v, want %v", w.cn, got, w.ofIn)
			}
		}
	})
}

// TestContractHostGroupMemberSpelling pins Q141's failure entries.
func TestContractHostGroupMemberSpelling(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newHostGroup(t, b)
		missing := "NoSuchHG" + randHex(t, 3)
		host := "NoHost" + randHex(t, 3) + ".invalid.test"
		failed := func(m string, opts ipa.Options) gjson.Result {
			t.Helper()
			return gjson.ParseBytes(mustRPC(t, b.admin, m, []string{cn}, opts).Result.Failed)
		}
		for _, w := range []struct {
			what, method, kind, name, msg string
		}{
			{"add unknown host group", "hostgroup_add_member", "hostgroup", missing, "no such entry"},
			{"add unknown host", "hostgroup_add_member", "host", host, "no such entry"},
			{"add itself", "hostgroup_add_member", "hostgroup", strings.ToUpper(cn), "A group may not be added as a member of itself"},
			{"remove unknown host group", "hostgroup_remove_member", "hostgroup", missing, "This entry is not a member"},
			{"remove unknown host", "hostgroup_remove_member", "host", host, "This entry is not a member"},
		} {
			f := failed(w.method, ipa.Options{w.kind: []string{w.name}})
			got := f.Get("member." + w.kind + ".0")
			if got.Get("0").String() != w.name || got.Get("1").String() != w.msg {
				t.Errorf("%s: failed %s, want [%q, %q]", w.what, f.Raw, w.name, w.msg)
			}
		}
	})
}

// TestContractHostGroupDenied pins Q141's denial texts.
func TestContractHostGroupDenied(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn, other := newHostGroup(t, b), newServiceUser(t, b)
		plain := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		prefix := func(attr string) string {
			return "Insufficient access: Insufficient 'write' privilege to the '" + attr + "' attribute of entry 'cn=" + cn + ",cn=hostgroups,cn=accounts,"
		}
		for _, w := range []struct {
			method, key, kind, name, attr string
		}{
			{"hostgroup_add_member", "member", "host", serverHost(t, b), "member"},
			{"hostgroup_add_member_manager", "membermanager", "user", other, "memberManager"},
			{"hostgroup_remove_member_manager", "membermanager", "user", other, "memberManager"},
		} {
			res := mustRPC(t, plain, w.method, []string{cn}, ipa.Options{w.kind: []string{w.name}})
			got := gjson.GetBytes(res.Result.Failed, w.key+"."+w.kind+".0.1").String()
			if !strings.HasPrefix(got, prefix(w.attr)) || res.Result.Completed != 0 {
				t.Errorf("%s: %q (completed %d), want prefix %q", w.method, got, res.Result.Completed, prefix(w.attr))
			}
		}
	})
}

// TestContractHostGroupDeleteKeepsAutomember pins Q147.
func TestContractHostGroupDeleteKeepsAutomember(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		for _, typ := range []string{ipa.AutomemberHostGroup, ipa.AutomemberGroup} {
			cn := "am" + randHex(t, 4)
			mustRPC(t, b.admin, typ+"_add", []string{cn}, nil)
			if _, err := b.admin.AutomemberAdd(typ, cn, ""); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.admin.AutomemberDelete(typ, cn) })
			mustRPC(t, b.admin, typ+"_del", []string{cn}, nil)
			if r, err := b.admin.AutomemberShow(typ, cn); err != nil || r.Name != cn {
				t.Errorf("%s rule after %s_del: %+v, %v", typ, typ, r, err)
			}
		}
	})
}

// TestContractServiceAuthIndicators pins Q142.
func TestContractServiceAuthIndicators(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		principal := "goipa" + randHex(t, 4) + "/" + serverHost(t, b) + "@" + b.realm
		_, err := b.admin.RPC("service_add", []string{principal}, ipa.Options{"force": true, "krbprincipalauthind": []string{"bogus"}})
		wantCode(t, "service_add bogus", err, ipa.CodeValidation)
		mustRPC(t, b.admin, "service_add", []string{principal}, ipa.Options{"force": true, "krbprincipalauthind": []string{"otp"}})
		t.Cleanup(func() { _ = b.admin.ServiceDelete(principal) })
		inds := func() []string {
			t.Helper()
			svc, err := b.admin.ServiceShow(principal)
			if err != nil {
				t.Fatal(err)
			}
			return svc.AuthIndicators
		}
		if got := inds(); !slices.Equal(got, []string{"otp"}) {
			t.Errorf("after add: %v", got)
		}
		if _, err := b.admin.Modify("service_mod", principal).Set("krbprincipalauthind", "pkinit").Add("krbprincipalauthind", "hardened").Run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := inds(); !slices.Equal(got, []string{"pkinit", "hardened"}) {
			t.Errorf("after Modify: %v", got)
		}
		_, err = b.admin.Modify("service_mod", principal).Add("krbprincipalauthind", "hardened").Run(ctx)
		wantIs(t, err, ipa.ErrEmptyModlist)
		_, err = b.admin.Modify("service_mod", principal).Set("krbprincipalauthind", "bogus").Run(ctx)
		wantCode(t, "setattr bogus", err, ipa.CodeValidation)
		_, err = b.admin.RPC("service_mod", []string{principal}, ipa.Options{"krbprincipalauthind": []string{"bogus"}})
		wantCode(t, "option bogus", err, ipa.CodeValidation)
		mustRPC(t, b.admin, "service_mod", []string{principal}, ipa.Options{"krbprincipalauthind": []string{"radius"}})
		if got := inds(); !slices.Equal(got, []string{"radius"}) {
			t.Errorf("after option: %v", got)
		}
		if _, err := b.admin.Modify("service_mod", principal).Set("krbprincipalauthind", "").Run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := inds(); len(got) != 0 {
			t.Errorf("after clear: %v", got)
		}
		_, err = b.admin.Modify("service_mod", principal).Del("krbprincipalauthind", "otp").Run(ctx)
		wantMessage(t, "delattr on none", err, ipa.CodeValidation, "invalid 'krbprincipalauthind': No such attribute on this entry")
	})
}

// TestContractDNSApexAndNames pins Q143.
func TestContractDNSApexAndNames(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		zone := newZone(t, b)
		bare := strings.TrimSuffix(zone, ".")
		wantMessage(t, "del_all @", b.admin.DNSRecordDelete(zone, "@"), ipa.CodeValidation, "invalid 'del_all': Zone record '@' cannot be deleted")
		ns := gjson.GetBytes(mustRPC(t, b.admin, "dnsrecord_show", []string{zone, "@"}, nil).Result.Data, "nsrecord.0").String()
		mustRPC(t, b.admin, "dnsrecord_del", []string{zone, "@"}, ipa.Options{"nsrecord": []string{ns}})
		if _, err := b.admin.DNSRecordShow(zone, "@"); err != nil {
			t.Errorf("apex after its last record: %v", err)
		}
		_, err := b.admin.RPC("dnsrecord_del", []string{zone, "@"}, ipa.Options{"nsrecord": []string{ns}})
		wantMessage(t, "del absent NS", err, ipa.CodeAttrValueNotFound, "NS record does not contain '"+ns+"'")

		_, err = b.admin.RPC("dnsrecord_add", []string{zone, "z.other.test."}, ipa.Options{"arecord": []string{"192.0.2.4"}})
		wantMessage(t, "out of zone", err, ipa.CodeValidation, "invalid 'idnsname': out-of-zone data: record name must be a subdomain of the zone or a relative name")
		name := "x." + bare
		res := mustRPC(t, b.admin, "dnsrecord_add", []string{zone, name}, ipa.Options{"arecord": []string{"192.0.2.1"}})
		if len(res.Result.Messages) != 1 || res.Result.Messages[0].Code != 13014 || res.Result.Messages[0].Name != "DNSSuspiciousRelativeName" {
			t.Errorf("messages = %+v", res.Result.Messages)
		}
		if r, err := b.admin.DNSRecordShow(zone, name); err != nil || r.Name != name {
			t.Errorf("relative name kept: %+v, %v", r, err)
		}
	})
}

// TestContractCertPrincipalCase pins Q144.
func TestContractCertPrincipalCase(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newCertHost(t, b)
		_, err := b.admin.CertRequest("host/"+strings.ToUpper(fqdn), csrFor(t, fqdn))
		wantMessage(t, "upper-case principal", err, ipa.CodeNotFound, "The principal for this request doesn't exist.")
		cert, err := b.admin.CertRequest("host/"+fqdn, csrFor(t, strings.ToUpper(fqdn)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.CertRevoke(cert.SerialNumber, 4) })
		if !strings.HasPrefix(cert.Subject, "CN="+strings.ToUpper(fqdn)+",") {
			t.Errorf("subject %q", cert.Subject)
		}
	})
}

// TestContractCertRevokeTwice pins Q145.
func TestContractCertRevokeTwice(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		fqdn := newCertHost(t, b)
		cert, err := b.admin.CertRequest("host/"+fqdn, csrFor(t, fqdn))
		if err != nil {
			t.Fatal(err)
		}
		if err := b.admin.CertRevoke(cert.SerialNumber, 4); err != nil {
			t.Fatal(err)
		}
		res, err := b.admin.Ping()
		if err != nil {
			t.Fatal(err)
		}
		code := 4301
		if strings.HasPrefix(res.Version, "4.12.") {
			code = 4035
		}
		wantCode(t, "second revoke", b.admin.CertRevoke(cert.SerialNumber, 1), code)
		shown, err := b.admin.CertShow(cert.SerialNumber)
		if err != nil || !shown.Revoked || shown.RevocationReason != 4 {
			t.Errorf("after second revoke: %+v, %v", shown, err)
		}
	})
}

// TestContractPasskeyAnswer pins Q36's answers and the 905 before 4.11.
func TestContractPasskeyAnswer(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		res, err := b.admin.Ping()
		if err != nil {
			t.Fatal(err)
		}
		if !serverAtLeast(res.Version, 4, 11) {
			_, err := b.rawAdmin().RPC("user_add_passkey", []string{uid, testPasskey}, nil)
			wantMessage(t, "before 4.11", err, ipa.CodeCommand, "unknown command 'user_add_passkey'")
			return
		}
		keys := func(r *ipa.Response) []string {
			var out []string
			gjson.ParseBytes(r.Result.Data).ForEach(func(k, _ gjson.Result) bool { out = append(out, k.String()); return true })
			slices.Sort(out)
			return out
		}
		if got := keys(mustRPC(t, b.admin, "user_add_passkey", []string{uid, testPasskey}, nil)); !slices.Equal(got, []string{"ipapasskey", "uid"}) {
			t.Errorf("add keys %v", got)
		}
		if got := keys(mustRPC(t, b.admin, "user_remove_passkey", []string{uid, testPasskey}, nil)); !slices.Equal(got, []string{"uid"}) {
			t.Errorf("remove keys %v", got)
		}
		r := mustRPC(t, b.admin, "user_add_passkey", []string{uid, testPasskey}, ipa.Options{"all": true})
		if d := gjson.ParseBytes(r.Result.Data); d.Get("givenname.0").String() != "Go" || d.Get("ipapasskey.0").String() != testPasskey {
			t.Errorf("all: %s", d.Raw)
		}
	})
}
