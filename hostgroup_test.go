// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func TestHostGroupShow(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("a.test.local", ipatest.Host{})
	s.AddHost("b.test.local", ipatest.Host{HostGroups: []string{"child"}})
	s.AddHostGroup("hg", ipatest.HostGroup{Description: "d", Hosts: []string{"a.test.local"}, HostGroups: []string{"child"},
		ManagerUsers: []string{"m"}, ManagerGroups: []string{"mg"}})
	s.AddHostGroup("child", ipatest.HostGroup{})
	s.AddHostGroup("top", ipatest.HostGroup{HostGroups: []string{"hg"}})
	g, err := c.HostGroupShow("hg")
	if err != nil {
		t.Fatal(err)
	}
	want := &ipa.HostGroup{Name: "hg", Description: "d", Hosts: []string{"a.test.local"}, HostGroups: []string{"child"},
		IndirectHosts: []string{"b.test.local"}, MemberOf: []string{"top"}, ManagerUsers: []string{"m"}, ManagerGroups: []string{"mg"}}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("got %+v, want %+v", g, want)
	}
	top, err := c.HostGroupShow("top")
	if err != nil || !reflect.DeepEqual(top.IndirectHostGroups, []string{"child"}) {
		t.Errorf("top = %+v, err = %v", top, err)
	}
	h, err := c.HostShow("b.test.local")
	if err != nil || !reflect.DeepEqual(h.HostGroups, []string{"child"}) || !reflect.DeepEqual(h.IndirectHostGroups, []string{"hg", "top"}) {
		t.Errorf("host = %+v, err = %v", h, err)
	}
}

func TestHostGroupShow_NotFound(t *testing.T) {
	_, c := newFake(t)
	_, err := c.HostGroupShow("nope")
	if _, ok := err.(*ipa.IpaError); !ok || !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("err = %v (%T), want bare not found", err, err)
	}
}

func TestHostGroup_NoRequest(t *testing.T) {
	s, c := newFake(t)
	for name, err := range map[string]error{
		"show":      func() error { _, err := c.HostGroupShow(""); return err }(),
		"add":       func() error { _, err := c.HostGroupAdd(&ipa.HostGroup{}); return err }(),
		"add nil":   func() error { _, err := c.HostGroupAdd(nil); return err }(),
		"delete":    c.HostGroupDelete(),
		"del gap":   c.HostGroupDelete("hg", ""),
		"member":    func() error { _, err := c.HostGroupAddMember("hg", nil, nil); return err }(),
		"no name":   func() error { _, err := c.HostGroupRemoveMember("", []string{"h"}, nil); return err }(),
		"managers":  func() error { _, err := c.HostGroupAddMemberManager("hg", nil, []string{}); return err }(),
		"rmmanager": func() error { _, err := c.HostGroupRemoveMemberManager("hg", nil, nil); return err }(),
	} {
		if err == nil {
			t.Errorf("%s: nil error", name)
		}
	}
	if n := len(s.Calls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

func TestHostGroupFind_Truncated(t *testing.T) {
	s, c := newFake(t)
	s.AddHostGroup("a", ipatest.HostGroup{})
	s.AddHostGroup("b", ipatest.HostGroup{})
	gs, err := c.HostGroupFind(ipa.Options{"sizelimit": 1})
	if !errors.Is(err, ipa.ErrTruncated) || len(gs) != 1 || gs[0].Name != "a" {
		t.Fatalf("gs = %v, err = %v", gs, err)
	}
}

func TestHostGroupDelete_DropsReferences(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("a.test.local", ipatest.Host{HostGroups: []string{"hg"}})
	s.AddHostGroup("hg", ipatest.HostGroup{})
	s.AddHostGroup("p", ipatest.HostGroup{HostGroups: []string{"hg"}})
	if err := c.HostGroupDelete("hg"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.HostGroup("p"); len(p.HostGroups) != 0 {
		t.Errorf("p = %+v", p)
	}
	if h, err := c.HostShow("a.test.local"); err != nil || len(h.HostGroups) != 0 {
		t.Errorf("host = %+v, err = %v", h, err)
	}
}

func TestHostGroupMembers_Fake(t *testing.T) {
	s, c := newFake(t)
	s.AddHost("a.test.local", ipatest.Host{HostGroups: []string{"hg"}})
	s.AddHostGroup("hg", ipatest.HostGroup{})
	g, err := c.HostGroupAddMember("hg", []string{"a.test.local"}, []string{"hg"})
	var me *ipa.MemberError
	if !errors.As(err, &me) || len(me.Failures) != 2 || g == nil {
		t.Fatalf("g = %v, err = %v, want already-member and self failures", g, err)
	}
	if _, err := c.HostGroupRemoveMember("hg", []string{"a.test.local"}, nil); err != nil {
		t.Fatal(err)
	}
	if h, err := c.HostShow("a.test.local"); err != nil || len(h.HostGroups) != 0 {
		t.Errorf("host after remove = %+v, err = %v", h, err)
	}
	plain := s.ClientAs("bob")
	if _, err := plain.HostGroupAddMember("hg", []string{"a.test.local"}, nil); !errors.As(err, &me) {
		t.Errorf("plain user: err = %v, want *MemberError", err)
	}
	if hg, _ := s.HostGroup("hg"); len(hg.Hosts) != 0 {
		t.Errorf("hg = %+v", hg)
	}
}

func TestHostDelete_DropsReferences(t *testing.T) {
	s, c := newFake(t)
	h := "web1.test.local"
	s.AddHost(h, ipatest.Host{})
	s.AddHostGroup("web", ipatest.HostGroup{Hosts: []string{h}})
	s.AddHBACRule("r", ipatest.HBACRule{Hosts: []string{h}})
	s.AddSudoRule("s", ipatest.SudoRule{Hosts: []string{h}})
	s.AddService("HTTP/ipa.test.local", ipatest.Service{ManagedBy: []string{"ipa.test.local", h},
		KeytabRetrieve: ipa.KeytabAccess{Hosts: []string{h}}, KeytabCreate: ipa.KeytabAccess{Hosts: []string{h}}})
	if _, err := c.RPC("host_del", []string{"WEB1.test.local"}, nil); err != nil {
		t.Fatal(err)
	}
	if g, err := c.HostGroupShow("web"); err != nil || len(g.Hosts) != 0 {
		t.Errorf("host group = %+v, %v", g, err)
	}
	if r, err := c.HBACRuleShow("r"); err != nil || len(r.Hosts) != 0 {
		t.Errorf("hbac rule = %+v, %v", r, err)
	}
	if r, err := c.SudoRuleShow("s"); err != nil || len(r.Hosts) != 0 {
		t.Errorf("sudo rule = %+v, %v", r, err)
	}
	svc, err := c.ServiceShow("HTTP/ipa.test.local")
	if err != nil || !reflect.DeepEqual(svc.ManagedBy, []string{"ipa.test.local"}) ||
		len(svc.KeytabRetrieve.Hosts) != 0 || len(svc.KeytabCreate.Hosts) != 0 {
		t.Errorf("service = %+v, %v", svc, err)
	}
}

func TestHostGroupDelete_DropsRuleAndKeytabReferences(t *testing.T) {
	s, c := newFake(t)
	s.AddHostGroup("web", ipatest.HostGroup{})
	s.AddHBACRule("r", ipatest.HBACRule{HostGroups: []string{"web"}})
	s.AddSudoRule("s", ipatest.SudoRule{HostGroups: []string{"web"}})
	s.AddService("HTTP/ipa.test.local", ipatest.Service{ManagedBy: []string{"ipa.test.local"},
		KeytabRetrieve: ipa.KeytabAccess{HostGroups: []string{"web"}}, KeytabCreate: ipa.KeytabAccess{HostGroups: []string{"web"}}})
	if err := c.HostGroupDelete("web"); err != nil {
		t.Fatal(err)
	}
	if r, err := c.HBACRuleShow("r"); err != nil || len(r.HostGroups) != 0 {
		t.Errorf("hbac rule = %+v, %v", r, err)
	}
	if r, err := c.SudoRuleShow("s"); err != nil || len(r.HostGroups) != 0 {
		t.Errorf("sudo rule = %+v, %v", r, err)
	}
	svc, err := c.ServiceShow("HTTP/ipa.test.local")
	if err != nil || len(svc.KeytabRetrieve.HostGroups) != 0 || len(svc.KeytabCreate.HostGroups) != 0 {
		t.Errorf("service = %+v, %v", svc, err)
	}
}
