// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

var web = []string{"web"}

func TestHostGroupCase_Rules(t *testing.T) {
	s, c := newFake(t)
	s.AddHostGroup("web", ipatest.HostGroup{})
	s.AddHBACRule("h", ipatest.HBACRule{})
	s.AddSudoRule("s", ipatest.SudoRule{})
	s.AddService("HTTP/ipa.test.local", ipatest.Service{ManagedBy: []string{"ipa.test.local"}})

	if r, err := c.HBACRuleAddHost("h", nil, []string{"WEB"}); err != nil || !reflect.DeepEqual(r.HostGroups, web) {
		t.Errorf("hbac add = %+v, %v", r, err)
	}
	if r, err := c.HBACRuleRemoveHost("h", nil, []string{"Web"}); err != nil || len(r.HostGroups) != 0 {
		t.Errorf("hbac remove = %+v, %v", r, err)
	}
	if r, err := c.SudoRuleAddHost("s", nil, []string{"WEB"}); err != nil || !reflect.DeepEqual(r.HostGroups, web) {
		t.Errorf("sudo add = %+v, %v", r, err)
	}
	if r, err := c.SudoRuleRemoveHost("s", nil, []string{"Web"}); err != nil || len(r.HostGroups) != 0 {
		t.Errorf("sudo remove = %+v, %v", r, err)
	}
	a := ipa.KeytabAccess{HostGroups: []string{"WEB"}}
	if v, err := c.ServiceAllowRetrieveKeytab("HTTP/ipa.test.local", a); err != nil || !reflect.DeepEqual(v.KeytabRetrieve.HostGroups, web) {
		t.Errorf("keytab allow = %+v, %v", v, err)
	}
	if v, err := c.ServiceDisallowRetrieveKeytab("HTTP/ipa.test.local", ipa.KeytabAccess{HostGroups: []string{"Web"}}); err != nil || len(v.KeytabRetrieve.HostGroups) != 0 {
		t.Errorf("keytab disallow = %+v, %v", v, err)
	}
}

func TestHostGroupCase_Nested(t *testing.T) {
	s, c := newFake(t)
	s.AddHostGroup("web", ipatest.HostGroup{})
	s.AddHostGroup("parent", ipatest.HostGroup{})
	if g, err := c.HostGroupAddMember("PARENT", nil, []string{"WEB"}); err != nil || !reflect.DeepEqual(g.HostGroups, web) {
		t.Errorf("add = %+v, %v", g, err)
	}
	if g, err := c.HostGroupRemoveMember("parent", nil, []string{"Web"}); err != nil || len(g.HostGroups) != 0 {
		t.Errorf("remove = %+v, %v", g, err)
	}
}

func TestHostGroupCase_Automember(t *testing.T) {
	_, c := newFake(t)
	if _, err := c.HostGroupAdd(&ipa.HostGroup{Name: "web"}); err != nil {
		t.Fatal(err)
	}
	if r, err := c.AutomemberAdd(ipa.AutomemberHostGroup, "WEB", "d"); err != nil || r.Name != "web" {
		t.Fatalf("add = %+v, %v", r, err)
	}
	if _, err := c.AutomemberShow(ipa.AutomemberHostGroup, "Web"); err != nil {
		t.Errorf("show: %v", err)
	}
	if _, err := c.AutomemberAddCondition(ipa.AutomemberHostGroup, "Web", "fqdn", []string{"^a"}, nil); err != nil {
		t.Errorf("condition: %v", err)
	}
	if err := c.AutomemberDelete(ipa.AutomemberHostGroup, "WEB"); err != nil {
		t.Errorf("delete: %v", err)
	}
}

func TestHostGroupCase_Seeds(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("in.test.local", ipatest.Host{HostGroups: []string{"Web"}})
	s.AddHostGroup("web", ipatest.HostGroup{})
	s.AddHostGroup("parent", ipatest.HostGroup{HostGroups: []string{"WEB"}})
	s.AddHBACRule("r", ipatest.HBACRule{UserCategory: "all", ServiceCategory: "all", HostGroups: []string{"PARENT"}})
	s.AddSudoRule("s", ipatest.SudoRule{HostGroups: []string{"Web"}})
	s.AddService("HTTP/ipa.test.local", ipatest.Service{KeytabCreate: ipa.KeytabAccess{HostGroups: []string{"Web"}}})

	if got, err := c.HBACTest("alice", "in.test.local", "sshd", "r"); err != nil || !got.Granted {
		t.Errorf("hbactest = %+v, %v", got, err)
	}
	if r, err := c.HBACRuleShow("r"); err != nil || !reflect.DeepEqual(r.HostGroups, []string{"parent"}) {
		t.Errorf("hbac = %+v, %v", r, err)
	}
	if r, err := c.SudoRuleShow("s"); err != nil || !reflect.DeepEqual(r.HostGroups, web) {
		t.Errorf("sudo = %+v, %v", r, err)
	}
	if v, err := c.ServiceShow("HTTP/ipa.test.local"); err != nil || !reflect.DeepEqual(v.KeytabCreate.HostGroups, web) {
		t.Errorf("service = %+v, %v", v, err)
	}
	if h, err := c.HostShow("in.test.local"); err != nil || !reflect.DeepEqual(h.HostGroups, web) {
		t.Errorf("host = %+v, %v", h, err)
	}
	if err := c.HostGroupDelete("web"); err != nil {
		t.Fatal(err)
	}
	if r, _ := c.SudoRuleShow("s"); len(r.HostGroups) != 0 {
		t.Errorf("sudo after delete = %+v", r)
	}
	if v, _ := c.ServiceShow("HTTP/ipa.test.local"); len(v.KeytabCreate.HostGroups) != 0 {
		t.Errorf("service after delete = %+v", v)
	}
}
