// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/tidwall/gjson"
)

func TestHostGroup_AddShowFindDelete(t *testing.T) {
	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	_, err := c.RPC("hostgroup_add", nil, nil)
	wantIpaCode(t, "add without cn", err, ipa.CodeRequirement)
	g, err := c.HostGroupAdd(&ipa.HostGroup{Name: "Web", Description: "web servers"})
	if err != nil || g.Name != "web" || g.Description != "web servers" {
		t.Fatalf("add = %+v, %v", g, err)
	}
	_, err = c.HostGroupAdd(&ipa.HostGroup{Name: "WEB"})
	if err == nil || err.Error() != `ipa: error 4002 - host group with name "web" already exists` {
		t.Errorf("duplicate add: %v", err)
	}
	if _, err := c.HostGroupAdd(&ipa.HostGroup{Name: "db"}); err != nil {
		t.Fatal(err)
	}

	if g, err := c.HostGroupShow("WEB"); err != nil || g.Description != "web servers" {
		t.Errorf("show = %+v, %v", g, err)
	}
	_, err = c.HostGroupShow("none")
	wantIpaCode(t, "show missing", err, ipa.CodeNotFound)
	_, err = c.RPC("hostgroup_show", nil, nil)
	wantIpaCode(t, "show without cn", err, ipa.CodeRequirement)
	all := gjson.ParseBytes(rpc(t, c, "hostgroup_show", []string{"web"}, ipa.Options{"all": true}).Result.Data)
	if all.Get("dn").String() != "cn=web,cn=hostgroups,cn=accounts,dc=test,dc=local" || all.Get("objectclass.1").String() != "ipahostgroup" {
		t.Errorf("show all = %s", all.Raw)
	}

	for _, tc := range []struct {
		args []string
		opts ipa.Options
		want []string
	}{
		{nil, nil, []string{"db", "web"}},
		{[]string{"SERVERS"}, nil, []string{"web"}},
		{nil, ipa.Options{"cn": "db"}, []string{"db"}},
		{nil, ipa.Options{"description": "web servers"}, []string{"web"}},
		{[]string{"zzz"}, nil, nil},
	} {
		if got := cns(rpc(t, c, "hostgroup_find", tc.args, tc.opts)); !slices.Equal(got, tc.want) {
			t.Errorf("find %v %v = %v, want %v", tc.args, tc.opts, got, tc.want)
		}
	}

	wantIpaCode(t, "delete missing", c.HostGroupDelete("db", "none"), ipa.CodeNotFound)
	if _, ok := s.HostGroup("db"); !ok {
		t.Error("failed delete removed a group")
	}
	if err := c.HostGroupDelete("DB", "web"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.HostGroup("web"); ok {
		t.Error("group survived delete")
	}
}

// TestHostGroupDel_DropsReferences pins Review Focus 4: a deleted host group
// leaves no reference behind.
func TestHostGroupDel_DropsReferences(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddHostGroup("old", ipatest.HostGroup{})
	s.AddHostGroup("parent", ipatest.HostGroup{HostGroups: []string{"old"}})
	s.AddHost("h.test.local", ipatest.Host{HostGroups: []string{"old"}})
	s.AddHBACRule("allow", ipatest.HBACRule{HostGroups: []string{"old"}})
	s.AddSudoRule("sudo", ipatest.SudoRule{HostGroups: []string{"old"}})
	s.AddService("HTTP/h.test.local", ipatest.Service{KeytabRetrieve: ipa.KeytabAccess{HostGroups: []string{"old"}},
		KeytabCreate: ipa.KeytabAccess{HostGroups: []string{"old"}}})
	c := s.ClientAs("admin")
	if err := c.HostGroupDelete("old"); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.HostGroup("parent"); len(g.HostGroups) != 0 {
		t.Errorf("parent = %+v", g)
	}
	if h, err := c.HostShow("h.test.local"); err != nil || len(h.HostGroups) != 0 {
		t.Errorf("host = %+v, %v", h, err)
	}
	if r, _ := s.HBACRule("allow"); len(r.HostGroups) != 0 {
		t.Errorf("hbac rule = %+v", r)
	}
	if r, _ := s.SudoRule("sudo"); len(r.HostGroups) != 0 {
		t.Errorf("sudo rule = %+v", r)
	}
	if v, _ := s.Service("HTTP/h.test.local"); len(v.KeytabRetrieve.HostGroups)+len(v.KeytabCreate.HostGroups) != 0 {
		t.Errorf("service = %+v", v)
	}
}

func TestHostGroup_Nesting(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddHost("a.test.local", ipatest.Host{HostGroups: []string{"leaf"}})
	s.AddHost("b.test.local", ipatest.Host{})
	s.AddHostGroup("leaf", ipatest.HostGroup{Hosts: []string{"b.test.local"}})
	s.AddHostGroup("mid", ipatest.HostGroup{HostGroups: []string{"LEAF"}})
	s.AddHostGroup("top", ipatest.HostGroup{HostGroups: []string{"mid"}})
	c := s.ClientAs("admin")

	top, err := c.HostGroupShow("top")
	if err != nil || !slices.Equal(top.HostGroups, []string{"mid"}) || !slices.Equal(top.IndirectHostGroups, []string{"leaf"}) ||
		!slices.Equal(top.IndirectHosts, []string{"a.test.local", "b.test.local"}) {
		t.Errorf("top = %+v, %v", top, err)
	}
	leaf, _ := c.HostGroupShow("leaf")
	if !slices.Equal(leaf.Hosts, []string{"b.test.local", "a.test.local"}) || !slices.Equal(leaf.MemberOf, []string{"mid"}) {
		t.Errorf("leaf = %+v", leaf)
	}
	r := gjson.ParseBytes(rpc(t, c, "hostgroup_show", []string{"leaf"}, nil).Result.Data)
	if r.Get("memberofindirect_hostgroup").Raw != `["top"]` {
		t.Errorf("leaf memberofindirect = %s", r.Raw)
	}

	s.AddHostGroup("leaf", ipatest.HostGroup{HostGroups: []string{"top"}}) // a cycle (Q140)
	r = gjson.ParseBytes(rpc(t, c, "hostgroup_show", []string{"top"}, nil).Result.Data)
	if !slices.Contains(strList(r.Get("memberindirect_hostgroup")), "top") {
		t.Errorf("cycle: top memberindirect_hostgroup = %s", r.Get("memberindirect_hostgroup").Raw)
	}
}

func TestHostGroup_Members(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddHost("a.test.local", ipatest.Host{})
	s.AddHost("b.test.local", ipatest.Host{HostGroups: []string{"web"}})
	s.AddHostGroup("web", ipatest.HostGroup{})
	s.AddHostGroup("sub", ipatest.HostGroup{})
	c := s.ClientAs("admin")

	g, err := c.HostGroupAddMember("web", []string{"a.test.local", "b.test.local", "ghost.test.local"}, []string{"SUB", "web", "none"})
	var merr *ipa.MemberError
	if !errors.As(err, &merr) {
		t.Fatalf("add: %v", err)
	}
	want := []ipa.MemberFailure{
		{Kind: "member", Type: "host", Name: "b.test.local", Message: "This entry is already a member"},
		{Kind: "member", Type: "host", Name: "ghost.test.local", Message: "no such entry"},
		{Kind: "member", Type: "hostgroup", Name: "web", Message: "A group may not be added as a member of itself"},
		{Kind: "member", Type: "hostgroup", Name: "none", Message: "no such entry"},
	}
	if !slices.Equal(merr.Failures, want) || !slices.Equal(g.HostGroups, []string{"sub"}) {
		t.Errorf("add failures = %+v, groups %v", merr.Failures, g.HostGroups)
	}
	if got, _ := s.HostGroup("web"); !slices.Equal(got.Hosts, []string{"a.test.local"}) {
		t.Errorf("stored hosts = %v", got.Hosts)
	}

	_, err = c.HostGroupRemoveMember("web", []string{"b.test.local", "a.test.local", "Ghost.test.local"}, []string{"sub"})
	if !errors.As(err, &merr) || !slices.Equal(merr.Failures, []ipa.MemberFailure{
		{Kind: "member", Type: "host", Name: "Ghost.test.local", Message: "This entry is not a member"}, // as given, not looked up (Q141)
	}) {
		t.Errorf("remove: %v", err)
	}
	if h, _ := c.HostShow("b.test.local"); len(h.HostGroups) != 0 {
		t.Errorf("b still in %v", h.HostGroups) // the membership lived in Host.HostGroups
	}
	if g, _ := c.HostGroupShow("web"); len(g.Hosts)+len(g.HostGroups) != 0 {
		t.Errorf("after remove = %+v", g)
	}
	_, err = c.HostGroupAddMember("none", []string{"a.test.local"}, nil)
	wantIpaCode(t, "missing group", err, ipa.CodeNotFound)
}

func TestHostGroup_MemberManagers(t *testing.T) {
	s := ipatest.NewServer(t)
	s.AddUser("mgr", ipatest.User{})
	s.AddUser("helper", ipatest.User{})
	s.AddUser("bob", ipatest.User{})
	s.AddGroup("ops", ipatest.Group{Members: []string{"helper"}})
	s.AddHost("a.test.local", ipatest.Host{})
	s.AddHostGroup("web", ipatest.HostGroup{})
	c := s.ClientAs("admin")

	_, err := c.HostGroupAddMemberManager("web", []string{"mgr", "nouser"}, []string{"ops"})
	var merr *ipa.MemberError
	if !errors.As(err, &merr) || len(merr.Failures) != 1 || merr.Failures[0] != (ipa.MemberFailure{Kind: "membermanager", Type: "user", Name: "nouser", Message: "no such entry"}) {
		t.Errorf("add managers: %v", err)
	}
	if _, err := c.HostGroupAddMemberManager("web", []string{"mgr"}, nil); !errors.As(err, &merr) || merr.Failures[0].Message != "This entry is already a member" {
		t.Errorf("add manager twice: %v", err)
	}

	// A manager, directly or through a group, may change members but not managers.
	if _, err := s.ClientAs("mgr").HostGroupAddMember("web", []string{"a.test.local"}, nil); err != nil {
		t.Errorf("manager add: %v", err)
	}
	if _, err := s.ClientAs("helper").HostGroupRemoveMember("web", []string{"a.test.local"}, nil); err != nil {
		t.Errorf("group manager remove: %v", err)
	}
	denied := "Insufficient access: Insufficient 'write' privilege to the 'memberManager' attribute of entry 'cn=web,cn=hostgroups,cn=accounts,dc=test,dc=local'."
	if _, err := s.ClientAs("mgr").HostGroupAddMemberManager("web", []string{"bob"}, nil); !errors.As(err, &merr) || merr.Failures[0].Message != denied {
		t.Errorf("manager adds manager: %v", err)
	}
	if _, err := s.ClientAs("bob").HostGroupAddMember("web", []string{"a.test.local"}, nil); !errors.As(err, &merr) ||
		merr.Failures[0].Message != "Insufficient access: Insufficient 'write' privilege to the 'member' attribute of entry 'cn=web,cn=hostgroups,cn=accounts,dc=test,dc=local'." {
		t.Errorf("non-manager add: %v", err)
	}
	if g, _ := s.HostGroup("web"); len(g.Hosts) != 0 || !slices.Equal(g.ManagerUsers, []string{"mgr"}) || !slices.Equal(g.ManagerGroups, []string{"ops"}) {
		t.Errorf("stored = %+v", g)
	}

	if _, err := c.HostGroupRemoveMemberManager("web", []string{"mgr", "bob"}, []string{"ops"}); !errors.As(err, &merr) ||
		len(merr.Failures) != 1 || merr.Failures[0].Message != "This entry is not a member" {
		t.Errorf("remove managers: %v", err)
	}
	if g, _ := s.HostGroup("web"); len(g.ManagerUsers)+len(g.ManagerGroups) != 0 {
		t.Errorf("managers after remove = %+v", g)
	}
}
