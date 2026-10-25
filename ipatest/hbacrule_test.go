// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func TestHBACRule_ShowToggleDelete(t *testing.T) {
	s, c := ruleServer(t)
	r, err := c.HBACRuleShow("h1")
	if err != nil || r.Description != "web access" || !r.Enabled || !slices.Equal(r.Users, []string{"alice"}) {
		t.Errorf("show = %+v, %v", r, err)
	}
	if got := gjson.ParseBytes(rpc(t, c, "hbacrule_show", []string{"h1"}, ipa.Options{"no_members": true}).Result.Data); got.Get("memberuser_user").Exists() {
		t.Errorf("no_members show = %s", got.Raw)
	}
	_, err = c.HBACRuleShow("none")
	wantIpaCode(t, "show missing", err, ipa.CodeNotFound)
	_, err = c.RPC("hbacrule_show", nil, nil)
	wantIpaCode(t, "show without cn", err, ipa.CodeRequirement)

	if err := c.HBACRuleDisable("h1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.HBACRule("h1"); !r.Disabled {
		t.Error("disable did not stick")
	}
	if err := c.HBACRuleEnable("h1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.HBACRule("h1"); r.Disabled {
		t.Error("enable did not stick")
	}
	wantIpaCode(t, "enable missing", c.HBACRuleEnable("none"), ipa.CodeNotFound)

	wantIpaCode(t, "delete with a missing rule", c.HBACRuleDelete("h1", "none"), ipa.CodeNotFound)
	if _, ok := s.HBACRule("h1"); !ok {
		t.Error("failed delete removed a rule")
	}
	if err := c.HBACRuleDelete("h1", "h2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.HBACRule("h2"); ok {
		t.Error("rule survived delete")
	}
}

func TestHBACRule_HostsAndServices(t *testing.T) {
	s, c := ruleServer(t)
	s.AddHost("web.test.local", ipatest.Host{})
	s.AddHostGroup("webs", ipatest.HostGroup{})
	var merr *ipa.MemberError

	r, err := c.HBACRuleAddHost("h1", []string{"web.test.local", "ghost.test.local"}, []string{"WEBS"})
	if !errors.As(err, &merr) || len(merr.Failures) != 1 || merr.Failures[0].Message != "no such entry" ||
		!slices.Equal(r.Hosts, []string{"web.test.local"}) || !slices.Equal(r.HostGroups, []string{"webs"}) {
		t.Errorf("add host = %+v, %v", r, err)
	}
	r, err = c.HBACRuleAddService("h1", []string{"sshd", "telnet"}, []string{"Sudo"})
	if !errors.As(err, &merr) || merr.Failures[0] != (ipa.MemberFailure{Kind: "memberservice", Type: "hbacsvc", Name: "telnet", Message: "no such entry"}) ||
		!slices.Equal(r.Services, []string{"sshd"}) || !slices.Equal(r.ServiceGroups, []string{"Sudo"}) {
		t.Errorf("add service = %+v, %v", r, err)
	}
	if _, err := c.HBACRuleRemoveHost("h1", []string{"web.test.local"}, []string{"webs"}); err != nil {
		t.Error(err)
	}
	if _, err := c.HBACRuleRemoveService("h1", []string{"sshd", "ftp"}, nil); !errors.As(err, &merr) || merr.Failures[0].Message != "This entry is not a member" {
		t.Errorf("remove service: %v", err)
	}
	if got, _ := s.HBACRule("h1"); len(got.Hosts)+len(got.HostGroups)+len(got.Services) != 0 || !slices.Equal(got.ServiceGroups, []string{"Sudo"}) {
		t.Errorf("stored = %+v", got)
	}

	s.AddHBACRule("anyhost", ipatest.HBACRule{HostCategory: "all", ServiceCategory: "all"})
	_, err = c.HBACRuleAddHost("anyhost", []string{"web.test.local"}, nil)
	if err == nil || err.Error() != "ipa: error 4303 - hosts cannot be added when host category='all'" {
		t.Errorf("host category all: %v", err)
	}
	_, err = c.HBACRuleAddService("anyhost", []string{"sshd"}, nil)
	wantIpaCode(t, "service category all", err, 4303)
	_, err = c.HBACRuleAddHost("none", []string{"web.test.local"}, nil)
	wantIpaCode(t, "missing rule", err, ipa.CodeNotFound)
}

func TestHBACTest(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("alice", ipatest.User{Groups: []string{"devs"}})
	s.AddGroup("staff", ipatest.Group{MemberGroups: []string{"devs"}})
	s.AddGroup("devs", ipatest.Group{})
	s.AddHost("web.test.local", ipatest.Host{HostGroups: []string{"webs"}})
	s.AddHostGroup("webs", ipatest.HostGroup{})
	s.AddHostGroup("all-servers", ipatest.HostGroup{HostGroups: []string{"webs"}})
	s.AddHBACRule("staff-sudo", ipatest.HBACRule{Groups: []string{"staff"}, HostGroups: []string{"all-servers"}, ServiceGroups: []string{"Sudo"}})
	s.AddHBACRule("ssh-only", ipatest.HBACRule{Users: []string{"alice"}, HostCategory: "all", Services: []string{"sshd"}})
	s.AddHBACRule("off", ipatest.HBACRule{UserCategory: "all", HostCategory: "all", ServiceCategory: "all", Disabled: true})
	c := s.ClientAs("admin")
	if err := c.HBACRuleDisable("allow_all"); err != nil {
		t.Fatal(err)
	}

	r, err := c.HBACTest("alice", "web.test.local", "sudo")
	if err != nil || !r.Granted || !slices.Equal(r.Matched, []string{"staff-sudo"}) || !slices.Equal(r.NotMatched, []string{"ssh-only"}) {
		t.Errorf("sudo = %+v, %v", r, err) // through nested user and host groups and the Sudo service group
	}
	if r, err := c.HBACTest("bob", "db.test.local", "sshd"); err != nil || r.Granted || len(r.Matched) != 0 {
		t.Errorf("unknown user = %+v, %v", r, err)
	}
	if r, err := c.HBACTest("alice", "db.test.local", "sshd", "off", "ssh-only"); err != nil || !r.Granted || !slices.Equal(r.Matched, []string{"off", "ssh-only"}) {
		t.Errorf("named rules = %+v, %v", r, err) // --rules tests disabled rules too
	}
	if r, err := c.HBACTest("alice", "web.test.local", "sshd", "nosuch", "ssh-only"); err != nil || r.Granted || !slices.Equal(r.Errors, []string{"nosuch"}) || r.Matched != nil {
		t.Errorf("unresolved rule = %+v, %v", r, err)
	}
	for _, missing := range []string{"user", "targethost", "service"} {
		opts := ipa.Options{"user": "alice", "targethost": "web.test.local", "service": "sshd"}
		delete(opts, missing)
		_, err := c.RPC("hbactest", nil, opts)
		wantIpaCode(t, "hbactest without "+missing, err, ipa.CodeRequirement)
	}
}

func TestSudoRule_ToggleAndMembers(t *testing.T) {
	s, c := ruleServer(t)
	s.AddHost("web.test.local", ipatest.Host{})
	rpc(t, c, "sudocmd_add", []string{"/bin/ls"}, nil)
	if err := c.SudoRuleDisable("s1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.SudoRule("s1"); !r.Disabled {
		t.Error("disable did not stick")
	}
	if err := c.SudoRuleEnable("s1"); err != nil {
		t.Fatal(err)
	}
	if err := c.SudoRuleEnable("s1"); err != nil {
		t.Errorf("enable twice (Q80): %v", err)
	}
	wantIpaCode(t, "enable missing", c.SudoRuleEnable("none"), ipa.CodeNotFound)

	if _, err := c.SudoRuleAddHost("s1", []string{"web.test.local", "Other.test.local"}, nil); err != nil {
		t.Fatal(err) // unknown hosts become externalhost (Q81)
	}
	if _, err := c.SudoRuleAddAllowCommand("s1", []string{"/bin/ls"}, nil); err != nil {
		t.Fatal(err)
	}
	var merr *ipa.MemberError
	if _, err := c.SudoRuleAddDenyCommand("s1", []string{"/bin/rm"}, []string{"grp"}); !errors.As(err, &merr) || len(merr.Failures) != 2 {
		t.Errorf("deny unknown command: %v", err)
	}
	if _, err := c.SudoRuleAddRunAsGroup("s1", []string{"wheel"}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.SudoRule("s1")
	if !slices.Equal(r.Hosts, []string{"web.test.local"}) || !slices.Equal(r.AllowCommands, []string{"/bin/ls"}) || len(r.DenyCommands) != 0 {
		t.Errorf("stored = %+v", r)
	}
	shown := gjson.ParseBytes(rpc(t, c, "sudorule_show", []string{"s1"}, nil).Result.Data)
	if shown.Get("externalhost").Raw != `["other.test.local"]` || shown.Get("ipasudorunasextgroup").Raw != `["wheel"]` {
		t.Errorf("show = %s", shown.Raw)
	}

	s.AddSudoRule("anyrunas", ipatest.SudoRule{RunAsGroupCategory: "all"})
	_, err := c.SudoRuleAddRunAsUser("anyrunas", []string{"alice"}, nil)
	if err == nil || err.Error() != "ipa: error 4303 - users cannot be added when runAs user or runAs group category='all'" {
		t.Errorf("runas category all: %v", err)
	}
	_, err = c.SudoRuleAddHost("none", []string{"web.test.local"}, nil)
	wantIpaCode(t, "missing rule", err, ipa.CodeNotFound)
}

func TestHost_AddDel(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	_, err := c.RPC("host_add", nil, nil)
	wantIpaCode(t, "add without fqdn", err, ipa.CodeRequirement)
	rpc(t, c, "host_add", []string{"Web.test.local"}, ipa.Options{"description": "web"})
	_, err = c.RPC("host_add", []string{"web.test.local"}, nil)
	wantIpaCode(t, "duplicate add", err, ipa.CodeDuplicateEntry)
	if h, err := c.HostShow("web.test.local"); err != nil || h.Description != "web" {
		t.Errorf("show = %+v, %v", h, err)
	}

	// Review Focus 4: a deleted host takes its services along and leaves no reference.
	s.AddHostGroup("webs", ipatest.HostGroup{Hosts: []string{"web.test.local"}})
	s.AddHBACRule("allow", ipatest.HBACRule{Hosts: []string{"web.test.local"}})
	s.AddSudoRule("sudo", ipatest.SudoRule{Hosts: []string{"web.test.local"}})
	s.AddHost("db.test.local", ipatest.Host{})
	s.AddService("HTTP/web.test.local", ipatest.Service{})
	s.AddService("HTTP/db.test.local", ipatest.Service{ManagedBy: []string{"db.test.local", "web.test.local"},
		KeytabRetrieve: ipa.KeytabAccess{Hosts: []string{"web.test.local"}}, KeytabCreate: ipa.KeytabAccess{Hosts: []string{"web.test.local"}}})
	_, err = c.RPC("host_del", []string{"web.test.local", "none.test.local"}, nil)
	wantIpaCode(t, "delete with a missing host", err, ipa.CodeNotFound)
	rpc(t, c, "host_del", []string{"WEB.test.local"}, nil)
	if _, err := c.HostShow("web.test.local"); err == nil {
		t.Error("host survived delete")
	}
	if _, ok := s.Service("HTTP/web.test.local"); ok {
		t.Error("the host's service survived")
	}
	v, _ := s.Service("HTTP/db.test.local")
	if !slices.Equal(v.ManagedBy, []string{"db.test.local"}) || len(v.KeytabRetrieve.Hosts)+len(v.KeytabCreate.Hosts) != 0 {
		t.Errorf("other service = %+v", v)
	}
	g, _ := s.HostGroup("webs")
	h, _ := s.HBACRule("allow")
	r, _ := s.SudoRule("sudo")
	if len(g.Hosts)+len(h.Hosts)+len(r.Hosts) != 0 {
		t.Errorf("references left: %v %v %v", g.Hosts, h.Hosts, r.Hosts)
	}
}

func TestSubID(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("alice", ipatest.User{})
	s.AddUser("bob", ipatest.User{})
	first := s.AddSubID(ipatest.SubID{Owner: "alice", Description: "seeded"})
	if first.ID == "" || first.UIDStart != 2147483648 || first.UIDCount != 65536 || first.GIDStart != first.UIDStart || first.GIDCount != 65536 {
		t.Errorf("AddSubID defaults = %+v", first)
	}
	c := s.ClientAs("admin")
	_, err := c.SubIDGenerate("alice")
	if err == nil || err.Error() != `ipa: error 4002 - Subordinate id with with name "`+first.ID+`" or for user "alice" already exists.` {
		t.Errorf("generate twice: %v", err)
	}
	_, err = c.SubIDGenerate("ghost")
	wantIpaCode(t, "generate for a missing user", err, ipa.CodeNotFound)
	r, err := c.SubIDGenerate("bob")
	if err != nil || r.Owner != "bob" || r.UIDStart != first.UIDStart+65536 {
		t.Errorf("generate = %+v, %v", r, err) // the next free range
	}
	if got, ok := s.SubID("bob"); !ok || got.ID != r.ID {
		t.Errorf("SubID(bob) = %+v, %v", got, ok)
	}
	if _, ok := s.SubID("ghost"); ok {
		t.Error("SubID found a missing owner")
	}
	if _, err := s.ClientAs("bob").RPC("subid_generate", nil, nil); err == nil {
		t.Error("self generate for an owner with a range succeeded") // the owner defaults to the caller
	}

	for _, tc := range []struct {
		opts ipa.Options
		want []string
	}{{nil, []string{"alice", "bob"}}, {ipa.Options{"ipaowner": "bob"}, []string{"bob"}}, {ipa.Options{"description": "seeded"}, []string{"alice"}}} {
		list, err := c.SubIDFind(tc.opts)
		var owners []string
		for _, r := range list {
			owners = append(owners, r.Owner)
		}
		if err != nil || !slices.Equal(owners, tc.want) {
			t.Errorf("find %v = %v, %v", tc.opts, owners, err)
		}
	}
}

func TestUserStatusAndUnlock(t *testing.T) {
	s := ipatest.NewServer(t)
	failed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.AddUser("bob", ipatest.User{FailedLogins: 3, LastFailedLogin: failed, Locked: true})
	s.AddUser("clean", ipatest.User{})
	c := s.ClientAs("admin")

	st, err := c.UserStatus("bob")
	if err != nil || len(st) != 1 || st[0].FailedLogins != 3 || !st[0].LastFailure.Equal(failed) || !st[0].LastSuccess.IsZero() || st[0].Now.IsZero() {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if st, err := c.UserStatus("clean"); err != nil || st[0].FailedLogins != 0 || !st[0].LastFailure.IsZero() {
		t.Errorf("clean status = %+v, %v", st, err)
	}
	if got := rpc(t, c, "user_status", []string{"bob"}, nil).Result.Summary; got != "Account disabled: True" {
		t.Errorf("summary = %q", got)
	}
	_, err = c.UserStatus("ghost")
	wantIpaCode(t, "status of a missing user", err, ipa.CodeNotFound)

	if err := c.UserUnlock("bob"); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User("bob"); u.FailedLogins != 0 || !u.Locked {
		t.Errorf("after unlock = %+v", u) // unlock clears the counter, not the disabled flag
	}
	wantIpaCode(t, "unlock a missing user", c.UserUnlock("ghost"), ipa.CodeNotFound)
}
