// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func serviceServer(t *testing.T) (*ipatest.Server, *ipa.Client) {
	s := ipatest.NewServer(t)
	s.AddHost("web.test.local", ipatest.Host{})
	s.AddUser("alice", ipatest.User{})
	s.AddGroup("ops", ipatest.Group{})
	s.AddHostGroup("webs", ipatest.HostGroup{})
	return s, s.ClientAs("admin")
}

func TestService_AddShowFindDelete(t *testing.T) {
	s, c := serviceServer(t)
	_, err := c.RPC("service_add", nil, nil)
	wantIpaCode(t, "add without principal", err, ipa.CodeRequirement)
	_, err = c.RPC("service_add", []string{"HTTP/nohost.test.local"}, nil)
	if err == nil || err.Error() != "ipa: error 4001 - The host 'nohost.test.local' does not exist to add a service to." {
		t.Errorf("add for a missing host: %v", err)
	}
	if _, err := c.RPC("service_add", []string{"HTTP/nohost.test.local"}, ipa.Options{"skip_host_check": true}); err != nil {
		t.Errorf("skip_host_check: %v", err)
	}
	if v, ok := s.Service("HTTP/nohost.test.local"); !ok || v.ManagedBy != nil {
		t.Errorf("unchecked service = %+v, %v", v, ok)
	}

	v, err := c.ServiceAdd("HTTP/web.test.local", false)
	if err != nil || v.Principal != "HTTP/web.test.local@TEST.LOCAL" || !slices.Equal(v.ManagedBy, []string{"web.test.local"}) {
		t.Fatalf("add = %+v, %v", v, err)
	}
	_, err = c.ServiceAdd("HTTP/web.test.local@TEST.LOCAL", false)
	wantIpaCode(t, "duplicate add", err, ipa.CodeDuplicateEntry)
	_, err = c.RPC("service_add", []string{"ldap/web.test.local"}, ipa.Options{"krbprincipalauthind": []string{"bogus"}})
	wantIpaCode(t, "bad auth indicator", err, ipa.CodeValidation)

	_, err = c.ServiceShow("HTTP/none.test.local")
	wantIpaCode(t, "show missing", err, ipa.CodeNotFound)
	_, err = c.RPC("service_show", nil, nil)
	wantIpaCode(t, "show without principal", err, ipa.CodeRequirement)
	all := gjson.ParseBytes(rpc(t, c, "service_show", []string{"HTTP/web.test.local"}, ipa.Options{"all": true}).Result.Data)
	if all.Get("dn").String() != "krbprincipalname=HTTP/web.test.local@TEST.LOCAL,cn=services,cn=accounts,dc=test,dc=local" ||
		all.Get("ipakrbrequirespreauth").Bool() != true || all.Get("managedby_host.0").String() != "web.test.local" {
		t.Errorf("show all = %s", all.Raw)
	}
	if got := gjson.ParseBytes(rpc(t, c, "service_show", []string{"HTTP/web.test.local"}, ipa.Options{"no_members": true}).Result.Data); got.Get("managedby_host").Exists() {
		t.Errorf("no_members show = %s", got.Raw)
	}

	list, err := c.ServiceFind(ipa.Options{"krbcanonicalname": "HTTP/web.test.local"})
	if err != nil || len(list) != 1 || list[0].Principal != "HTTP/web.test.local@TEST.LOCAL" {
		t.Errorf("find by principal = %+v, %v", list, err)
	}
	res := rpc(t, c, "service_find", []string{"nohost"}, ipa.Options{"no_members": false})
	if r := gjson.ParseBytes(res.Result.Raw); r.Get("count").Int() != 1 {
		t.Errorf("find by needle = %s", res.Result.Raw)
	}

	wantIpaCode(t, "delete missing", c.ServiceDelete("HTTP/web.test.local", "HTTP/none.test.local"), ipa.CodeNotFound)
	if _, ok := s.Service("HTTP/web.test.local"); !ok {
		t.Error("failed delete removed a service")
	}
	if err := c.ServiceDelete("HTTP/web.test.local", "HTTP/nohost.test.local"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Service("HTTP/web.test.local"); ok {
		t.Error("service survived delete")
	}
}

func TestService_Mod(t *testing.T) {
	s, c := serviceServer(t)
	s.AddService("HTTP/web.test.local", ipatest.Service{AuthIndicators: []string{"otp"}})
	rpc(t, c, "service_mod", []string{"HTTP/web.test.local"}, ipa.Options{"krbprincipalauthind": []string{"radius"}})
	rpc(t, c, "service_mod", []string{"HTTP/web.test.local"}, ipa.Options{"addattr": "krbprincipalauthind=pkinit"})
	if v, _ := s.Service("HTTP/web.test.local"); !slices.Equal(v.AuthIndicators, []string{"radius", "pkinit"}) {
		t.Errorf("auth indicators = %v", v.AuthIndicators)
	}
	_, err := c.RPC("service_mod", []string{"HTTP/web.test.local"}, ipa.Options{"krbprincipalauthind": []string{"radius", "pkinit"}})
	wantIpaCode(t, "no change", err, ipa.CodeEmptyModlist)
	_, err = c.RPC("service_mod", []string{"HTTP/web.test.local"}, ipa.Options{"krbprincipalauthind": []string{"nope"}})
	wantIpaCode(t, "bad option", err, ipa.CodeValidation)
	_, err = c.RPC("service_mod", []string{"HTTP/web.test.local"}, ipa.Options{"setattr": "krbprincipalauthind=nope"})
	if err == nil || err.Error() != "ipa: error 3009 - invalid 'krbprincipalauthind': must be one of 'radius', 'otp', 'pkinit', 'hardened', 'idp', 'passkey'" {
		t.Errorf("bad setattr: %v", err)
	}
	_, err = c.RPC("service_mod", []string{"HTTP/web.test.local"}, ipa.Options{"setattr": "description=x"})
	wantIpaCode(t, "unknown attribute", err, ipa.CodeObjectclassViolation)
	_, err = c.RPC("service_mod", []string{"HTTP/none.test.local"}, nil)
	wantIpaCode(t, "missing service", err, ipa.CodeNotFound)
}

func TestService_Members(t *testing.T) {
	s, c := serviceServer(t)
	s.AddHost("db.test.local", ipatest.Host{})
	s.AddService("HTTP/web.test.local", ipatest.Service{ManagedBy: []string{"web.test.local"}})
	p := "HTTP/web.test.local"

	v, err := c.ServiceAddHost(p, []string{"db.test.local", "web.test.local", "ghost.test.local"})
	var merr *ipa.MemberError
	if !errors.As(err, &merr) || len(merr.Failures) != 2 || !slices.Equal(v.ManagedBy, []string{"web.test.local", "db.test.local"}) {
		t.Errorf("add host = %+v, %v", v, err)
	}
	if _, err := c.ServiceRemoveHost(p, []string{"db.test.local"}); err != nil {
		t.Error(err)
	}
	if _, err := c.ServiceRemoveHost(p, []string{"db.test.local"}); !errors.As(err, &merr) || merr.Failures[0].Message != "This entry is not a member" {
		t.Errorf("remove non-member: %v", err)
	}

	a := ipa.KeytabAccess{Users: []string{"alice"}, Groups: []string{"ops"}, Hosts: []string{"db.test.local"}, HostGroups: []string{"WEBS"}}
	if _, err := c.ServiceAllowRetrieveKeytab(p, a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ServiceAllowCreateKeytab(p, ipa.KeytabAccess{Users: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Service(p)
	want := ipa.KeytabAccess{Users: []string{"alice"}, Groups: []string{"ops"}, Hosts: []string{"db.test.local"}, HostGroups: []string{"webs"}}
	if !slices.Equal(got.KeytabRetrieve.Users, want.Users) || !slices.Equal(got.KeytabRetrieve.HostGroups, want.HostGroups) ||
		!slices.Equal(got.KeytabRetrieve.Groups, want.Groups) || !slices.Equal(got.KeytabCreate.Users, want.Users) {
		t.Errorf("stored access = %+v", got)
	}
	shown, err := c.ServiceShow(p)
	if err != nil || !slices.Equal(shown.KeytabRetrieve.Hosts, want.Hosts) || !slices.Equal(shown.KeytabCreate.Users, want.Users) {
		t.Errorf("show = %+v, %v", shown, err)
	}
	if _, err := c.ServiceDisallowRetrieveKeytab(p, a); err != nil {
		t.Error(err)
	}
	if _, err := c.ServiceDisallowCreateKeytab(p, ipa.KeytabAccess{Users: []string{"alice"}}); err != nil {
		t.Error(err)
	}
	if got, _ := s.Service(p); len(got.KeytabRetrieve.Users)+len(got.KeytabRetrieve.HostGroups)+len(got.KeytabCreate.Users) != 0 {
		t.Errorf("access after disallow = %+v", got)
	}
	_, err = c.ServiceAddHost("HTTP/none.test.local", []string{"db.test.local"})
	wantIpaCode(t, "missing service", err, ipa.CodeNotFound)
}

func TestService_DisableAndCerts(t *testing.T) {
	s, c := serviceServer(t)
	p := "HTTP/web.test.local"
	s.AddService(p, ipatest.Service{HasKeytab: true})
	_, err := c.RPC("service_add_cert", []string{p}, nil)
	wantIpaCode(t, "add_cert without cert", err, ipa.CodeRequirement)
	_, err = c.RPC("service_add_cert", []string{p}, ipa.Options{"usercertificate": "%%%"})
	wantIpaCode(t, "add_cert bad base64", err, ipa.CodeValidation)
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	rpc(t, c, "service_add_cert", []string{p}, ipa.Options{"usercertificate": base64.StdEncoding.EncodeToString(der)})
	if v, err := c.ServiceShow(p); err != nil || len(v.Certificates) != 1 || !slices.Equal(v.Certificates[0], der) {
		t.Errorf("show certs = %+v, %v", v, err)
	}

	s.SetVersion("4.12.2")
	if err := c.ServiceDisable(p); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.ServiceShow(p); v.HasKeytab || len(v.Certificates) != 1 {
		t.Errorf("4.12 disable = %+v, want keytab gone and certificate kept (Q64)", v)
	}
	wantIpaCode(t, "4.12 disable again", c.ServiceDisable(p), ipa.CodeAlreadyInactive)

	s.SetVersion("4.13.4")
	if err := c.ServiceDisable(p); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.ServiceShow(p); len(v.Certificates) != 0 {
		t.Errorf("4.13 disable kept certificates: %+v", v)
	}
	wantIpaCode(t, "4.13 disable again", c.ServiceDisable(p), ipa.CodeAlreadyInactive)
	wantIpaCode(t, "disable missing", c.ServiceDisable("HTTP/none.test.local"), ipa.CodeNotFound)
}
