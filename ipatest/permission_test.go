// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

type gatedWrite struct {
	method string
	args   []string
	opts   ipa.Options
	ldap   string // start of the 4.12.2 message after "Insufficient access: "
}

// permServer seeds one existing object per gated write.
func permServer(t *testing.T) (*ipatest.Server, []gatedWrite) {
	t.Helper()
	s := ipatest.NewServer(t)
	s.AddUser("bob", ipatest.User{})
	s.AddUser("other", ipatest.User{})
	s.AddGroup("g", ipatest.Group{})
	s.AddHost("h.test.local", ipatest.Host{})
	s.AddHostGroup("hg", ipatest.HostGroup{})
	s.AddService("svc/ipa.test.local", ipatest.Service{})
	s.AddHBACRule("hr", ipatest.HBACRule{})
	s.AddSudoRule("sr", ipatest.SudoRule{})
	return s, []gatedWrite{
		{"user_add", []string{"nu"}, ipa.Options{"givenname": "N", "sn": "U"}, "Could not read UPG Definition originfilter."},
		{"user_mod", []string{"other"}, ipa.Options{"title": "x"}, "Insufficient 'write' privilege to the 'title' attribute of entry 'uid=other,"},
		{"user_del", []string{"other"}, nil, "Insufficient 'delete' privilege to delete the entry 'uid=other,cn=users,"},
		{"stageuser_add", []string{"ns"}, ipa.Options{"givenname": "N", "sn": "S"}, "Insufficient 'add' privilege to add the entry 'uid=ns,cn=staged users,"},
		{"stageuser_add", []string{"np"}, ipa.Options{"givenname": "N", "sn": "P", "userpassword": "Secret123"}, "Insufficient 'add' privilege to the 'userPassword' attribute"},
		{"group_add", []string{"ng"}, nil, "Insufficient 'add' privilege to add the entry 'cn=ng,cn=groups,"},
		{"group_mod", []string{"g"}, ipa.Options{"description": "x"}, "Insufficient 'write' privilege to the 'description' attribute of entry 'cn=g,"},
		{"automember_add", []string{"g"}, ipa.Options{"type": "group"}, "Insufficient 'add' privilege to add the entry 'cn=g,cn=group,cn=automember,"},
		{"group_del", []string{"g"}, nil, "Insufficient 'delete' privilege to delete the entry 'cn=g,"},
		{"host_add", []string{"n.test.local"}, ipa.Options{"force": true}, "Insufficient 'add' privilege to add the entry 'fqdn=n.test.local,"},
		{"host_mod", []string{"h.test.local"}, ipa.Options{"description": "x"}, "Insufficient 'write' privilege to the 'description' attribute of entry 'fqdn=h.test.local,"},
		{"host_del", []string{"h.test.local"}, nil, "Insufficient 'delete' privilege to delete the entry 'fqdn=h.test.local,"},
		{"hostgroup_add", []string{"nhg"}, nil, "Insufficient 'add' privilege to add the entry 'cn=nhg,cn=hostgroups,"},
		{"hostgroup_del", []string{"hg"}, nil, "Insufficient 'delete' privilege to delete the entry 'cn=hg,"},
		{"service_add", []string{"nsvc/ipa.test.local"}, ipa.Options{"force": true}, "Insufficient 'add' privilege to add the entry 'krbprincipalname=nsvc/ipa.test.local@TEST.LOCAL,"},
		{"service_del", []string{"svc/ipa.test.local"}, nil, "Insufficient 'delete' privilege to delete the entry 'krbprincipalname=svc/ipa.test.local@TEST.LOCAL,"},
		{"hbacrule_add", []string{"nhr"}, nil, "Insufficient 'add' privilege to add the entry 'ipaUniqueID="},
		{"hbacrule_enable", []string{"hr"}, nil, "Insufficient 'write' privilege to the 'ipaEnabledFlag' attribute of entry 'ipauniqueid="},
		{"hbacrule_disable", []string{"hr"}, nil, "Insufficient 'write' privilege to the 'ipaEnabledFlag' attribute of entry 'ipauniqueid="},
		{"hbacrule_del", []string{"hr"}, nil, "Insufficient 'delete' privilege to delete the entry 'ipaUniqueID="},
		{"sudorule_add", []string{"nsr"}, nil, "Insufficient 'add' privilege to add the entry 'ipaUniqueID="},
		{"sudorule_del", []string{"sr"}, nil, "Insufficient 'delete' privilege to delete the entry 'ipaUniqueID="},
		{"dnszone_add", []string{"nz.test."}, nil, "Insufficient 'add' privilege to add the entry 'idnsname=nz.test.,cn=dns,"},
	}
}

// ungated is true for the writes whose message does not follow the release
// (Q170).
func ungated(method string) bool {
	return method == "hbacrule_enable" || method == "hbacrule_disable" || method == "automember_add"
}

// snapshot is what admin sees of w's target: the *_show answer or its error.
func snapshot(t *testing.T, s *ipatest.Server, w gatedWrite) string {
	t.Helper()
	show := w.method[:strings.LastIndex(w.method, "_")] + "_show"
	opts := ipa.Options{"all": true}
	if show == "automember_show" {
		opts["type"] = "group"
	}
	res, err := s.ClientAs("admin").RPC(show, w.args[:1], opts)
	if err != nil {
		return err.Error()
	}
	b, jerr := json.Marshal(res.Result)
	if jerr != nil {
		t.Fatal(jerr)
	}
	return string(b)
}

func TestPlainUserWriteRefused(t *testing.T) {
	s, writes := permServer(t)
	c := s.ClientAs("bob")
	for _, w := range writes {
		before := snapshot(t, s, w)
		_, err := c.RPC(w.method, w.args, w.opts)
		if _, bare := err.(*ipa.IpaError); !bare || !errors.Is(err, ipa.ErrACI) {
			t.Errorf("%s %v: %v, want ACIError", w.method, w.args, err)
		}
		if after := snapshot(t, s, w); after != before {
			t.Errorf("%s %v changed the target:\n%s\n%s", w.method, w.args, before, after)
		}
	}
}

func TestPlainUserMessageByVersion(t *testing.T) {
	for _, v := range []string{"4.9.13", "4.12.2", "4.13.4"} {
		t.Run(v, func(t *testing.T) {
			s, writes := permServer(t)
			s.SetVersion(v)
			c := s.ClientAs("bob")
			for _, w := range writes {
				want := "Insufficient access: not allowed to perform this operation"
				if v == "4.12.2" || ungated(w.method) {
					want = "Insufficient access: " + w.ldap
				}
				_, err := c.RPC(w.method, w.args, w.opts)
				var ie *ipa.IpaError
				if !errors.As(err, &ie) || !strings.HasPrefix(ie.Message, want) {
					t.Errorf("%s: %v, want %q…", w.method, err, want)
				}
			}
		})
	}
}

func TestAdminWriteAllowed(t *testing.T) {
	for _, who := range []string{"admin", "ann"} { // ann is in admins
		s, writes := permServer(t)
		s.AddUser("ann", ipatest.User{Groups: []string{"admins"}})
		c := s.ClientAs(who)
		for _, w := range writes {
			if _, err := c.RPC(w.method, w.args, w.opts); err != nil {
				t.Errorf("%s as %s: %v", w.method, who, err)
			}
		}
	}
}

// TestPlainUserMissingTarget: a missing entry is reported before the gate,
// as FreeIPA lets the operation report it.
func TestPlainUserMissingTarget(t *testing.T) {
	s, _ := permServer(t)
	_, err := s.ClientAs("bob").RPC("user_del", []string{"ghost"}, nil)
	if !errors.Is(err, ipa.ErrNotFound) {
		t.Errorf("user_del ghost: %v", err)
	}
}

func TestSelfServiceAllowed(t *testing.T) {
	s, _ := permServer(t)
	s.AddUser("bob", ipatest.User{Password: "Secret123"})
	c := s.ClientAs("bob")
	if err := c.UserAddPasskey("bob", "passkey:Z29pcGEtdGVzdC1pZA==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgJ0OGh7RCx0W7lUgaq4bbkS5+r9uuEXFc8lWWhNH0uphy0Xv4/2mTD9h4KbXWYcpr0bxLYvifagCSgDbVZZlcg=="); err != nil {
		t.Errorf("own passkey: %v", err)
	}
	if _, err := c.AddOTPToken(nil); err != nil {
		t.Errorf("own OTP token: %v", err)
	}
	if _, err := c.RPC("user_mod", []string{"bob"}, ipa.Options{"title": "x", "setattr": []string{"telephoneNumber=1"}}); err != nil {
		t.Errorf("own user_mod: %v", err)
	}
	if err := c.ChangePassword("bob", "Secret123", "Another-Secret-2", ""); err != nil {
		t.Errorf("own password: %v", err)
	}
}

// TestOwnUserModOutsideSelfService pins Q174.
func TestOwnUserModOutsideSelfService(t *testing.T) {
	s, _ := permServer(t)
	c := s.ClientAs("bob")
	for _, o := range []ipa.Options{
		{"mail": []string{"b@example.test"}},
		{"title": "x", "homedirectory": "/home/x"},
		{"setattr": []string{"mail=b@example.test"}},
	} {
		if _, err := c.RPC("user_mod", []string{"bob"}, o); !errors.Is(err, ipa.ErrACI) {
			t.Errorf("%v: %v", o, err)
		}
	}
	s.SetVersion("4.12.2")
	_, err := c.RPC("user_mod", []string{"bob"}, ipa.Options{"title": "x", "mail": []string{"b@example.test"}})
	if err == nil || !strings.Contains(err.Error(), "'mail' attribute of entry 'uid=bob,") {
		t.Errorf("4.12.2 text: %v", err)
	}
	s.GrantPrivilege("bob", "User Administrators")
	if _, err := c.RPC("user_mod", []string{"bob"}, ipa.Options{"mail": []string{"b@example.test"}}); err != nil {
		t.Errorf("granted: %v", err)
	}
}

func TestGrantPrivilege_ClearedOnUserDel(t *testing.T) {
	s, _ := permServer(t)
	s.GrantPrivilege("bob", "User Administrators")
	if err := s.ClientAs("admin").UserDelete(false, false, "bob"); err != nil {
		t.Fatal(err)
	}
	s.AddUser("bob", ipatest.User{})
	if _, err := s.ClientAs("bob").UserAdd(&ipa.User{Username: "nu", First: "N", Last: "U"}, false); !errors.Is(err, ipa.ErrACI) {
		t.Errorf("re-added bob kept the grant: %v", err)
	}
}

func TestGrantPrivilege_UserAdministrators(t *testing.T) {
	s, _ := permServer(t)
	s.GrantPrivilege("bob", "User Administrators")
	c := s.ClientAs("bob")
	if _, err := c.UserAdd(&ipa.User{Username: "nu", First: "N", Last: "U"}, false); err != nil {
		t.Errorf("user_add: %v", err)
	}
	if err := c.UserDelete(false, false, "other"); err != nil {
		t.Errorf("user_del: %v", err)
	}
	// The privilege covers users only.
	if _, err := c.GroupAdd(&ipa.Group{Name: "ng"}); !errors.Is(err, ipa.ErrACI) {
		t.Errorf("group_add: %v", err)
	}
	if _, err := s.ClientAs("other2").UserAdd(&ipa.User{Username: "nv", First: "N", Last: "V"}, false); !errors.Is(err, ipa.ErrACI) {
		t.Errorf("ungranted user_add: %v", err)
	}
}

func TestGrantPrivilege_PwPolicyReaders(t *testing.T) {
	s, _ := permServer(t)
	c := s.ClientAs("bob")
	if _, err := c.PwPolicyShow(""); !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("before grant: %v", err)
	}
	s.GrantPrivilege("bob", "Password Policy Readers")
	if p, err := c.PwPolicyShow(""); err != nil || p.Name != "global_policy" {
		t.Errorf("after grant: %+v, %v", p, err)
	}
	// Readers may not write group members (Q24).
	if _, err := c.GroupAddMember("g", []string{"other"}, nil); err == nil {
		t.Error("group_add_member went through")
	}
}

func TestGrantPrivilege_OtherChecks(t *testing.T) {
	s, _ := permServer(t)
	s.GrantPrivilege("bob", "RBAC Readers")
	s.GrantPrivilege("bob", "Group Administrators")
	c := s.ClientAs("bob")
	if _, err := c.RoleShow("User Administrator"); err != nil {
		t.Errorf("role_show: %v", err)
	}
	if _, err := c.GroupAddMember("g", []string{"other"}, nil); err != nil {
		t.Errorf("group_add_member: %v", err)
	}
	if _, err := c.GroupMod(&ipa.Group{Name: "g", Description: "x"}); err != nil {
		t.Errorf("group_mod: %v", err)
	}
}

// TestGrantPrivilege_UnknownPrivilege: like AddUser, GrantPrivilege takes any
// input; a name ipatest does not check grants nothing.
func TestGrantPrivilege_UnknownPrivilege(t *testing.T) {
	s, _ := permServer(t)
	s.GrantPrivilege("bob", "No Such Privilege")
	s.GrantPrivilege("ghost", "User Administrators")
	if _, err := s.ClientAs("bob").UserAdd(&ipa.User{Username: "nu", First: "N", Last: "U"}, false); !errors.Is(err, ipa.ErrACI) {
		t.Errorf("user_add: %v", err)
	}
}
