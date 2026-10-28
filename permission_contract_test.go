// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
)

// TestContractPlainUserWrites pins Q168–Q172: the typed writes as a user
// outside admins with no roles, and the self-service calls.
func TestContractPlainUserWrites(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		res, err := b.admin.RPC("ping", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		ver := res.Version
		uid := newUserWithPassword(t, b, goodPW)
		c := mustLogin(t, b, uid, goodPW)

		srvHost := serverHost(t, b)
		svc, _ := newService(t, b)
		other := newServiceUser(t, b)
		otherRec, err := b.admin.UserShow(other)
		if err != nil {
			t.Fatal(err)
		}
		otherRec.First = "Changed"
		victim := newServiceUser(t, b)
		group, gone := newGroup(t, b), newGroup(t, b)
		host := newHostFQDN(t, b)
		if _, err := b.admin.HostAdd(&ipa.Host{FQDN: host}, true, true); err != nil {
			t.Fatal(err)
		}
		hostGone := newHostFQDN(t, b)
		if _, err := b.admin.HostAdd(&ipa.Host{FQDN: hostGone}, true, false); err != nil {
			t.Fatal(err)
		}
		hg := newHostGroup(t, b)
		hbac := newHBACRule(t, b, ipa.HBACRule{})
		if err := b.admin.HBACRuleDisable(hbac.Name); err != nil {
			t.Fatal(err)
		}
		hbacGone := newHBACRule(t, b, ipa.HBACRule{})
		hbacOn := newHBACRule(t, b, ipa.HBACRule{})
		sudo := newSudoRule(t, b)
		zone := newZone(t, b)
		autoGroup := newGroup(t, b)

		newUser, newStage, newStagePW := newUID(t, b), newUID(t, b), newUID(t, b)
		t.Cleanup(func() {
			_ = b.admin.StageUserDelete(newStage)
			_ = b.admin.StageUserDelete(newStagePW)
		})
		newGroupName := "gg" + randHex(t, 4)
		t.Cleanup(func() { _ = b.admin.GroupDelete(newGroupName) })
		newHost := newHostFQDN(t, b)
		newHG := "hg" + randHex(t, 4)
		t.Cleanup(func() { _ = b.admin.HostGroupDelete(newHG) })
		newSvc := "goipa" + randHex(t, 4) + "/" + srvHost + "@" + b.realm
		t.Cleanup(func() { _ = b.admin.ServiceDelete(newSvc) })
		newHBAC, newSudo := "gr"+randHex(t, 4), "gs"+randHex(t, 4)
		t.Cleanup(func() {
			_ = b.admin.HBACRuleDelete(newHBAC)
			_ = b.admin.SudoRuleDelete(newSudo)
		})
		newZoneName := zoneName(t)
		t.Cleanup(func() { _ = b.admin.DNSZoneDelete(newZoneName) })
		t.Cleanup(func() { _ = b.admin.AutomemberDelete(ipa.AutomemberGroup, autoGroup) })

		user := func(u string) *ipa.User { return &ipa.User{Username: u, First: "Go", Last: "Test"} }
		// ldap is the start of the 4.12.2 text; gate false: every release answers it.
		// A mod names one of the modified attributes, not always the same (Q169).
		gated := []struct {
			name, ldap string
			gate       bool
			call       func() error
		}{
			{"UserAdd", "Could not read UPG Definition", true, func() error { _, err := c.UserAdd(user(newUser), false); return err }},
			{"UserMod", "Insufficient 'write' privilege to the '", true,
				func() error { _, err := c.UserMod(otherRec); return err }},
			{"UserDelete", "Insufficient 'delete' privilege to delete the entry 'uid=" + victim + ",", true,
				func() error { return c.UserDelete(false, false, victim) }},
			{"StageUserAdd", "Insufficient 'add' privilege to add the entry 'uid=" + newStage + ",cn=staged users,", true,
				func() error { _, err := c.StageUserAdd(user(newStage)); return err }},
			{"StageUserAddWithPassword", "Insufficient 'add' privilege to the 'userPassword' attribute", true, func() error {
				_, err := c.StageUserAddWithPassword(user(newStagePW), goodPW)
				return err
			}},
			{"GroupAdd", "Insufficient 'add' privilege to add the entry 'cn=" + newGroupName + ",", true,
				func() error { _, err := c.GroupAdd(&ipa.Group{Name: newGroupName}); return err }},
			{"GroupMod", "Insufficient 'write' privilege to the '", true,
				func() error { _, err := c.GroupMod(&ipa.Group{Name: group, Description: "changed"}); return err }},
			{"GroupDelete", "Insufficient 'delete' privilege to delete the entry 'cn=" + gone + ",", true,
				func() error { return c.GroupDelete(gone) }},
			{"HostAdd", "Insufficient 'add' privilege to add the entry 'fqdn=" + newHost + ",", true,
				func() error { _, err := c.HostAdd(&ipa.Host{FQDN: newHost}, true, false); return err }},
			{"HostMod", "Insufficient 'write' privilege to the '", true,
				func() error { _, err := c.HostMod(&ipa.Host{FQDN: host, Description: "changed"}); return err }},
			{"HostDelete", "Insufficient 'delete' privilege to delete the entry 'fqdn=" + hostGone + ",", true,
				func() error { return c.HostDelete(false, hostGone) }},
			{"HostGroupAdd", "Insufficient 'add' privilege to add the entry 'cn=" + newHG + ",", true,
				func() error { _, err := c.HostGroupAdd(&ipa.HostGroup{Name: newHG}); return err }},
			{"HostGroupDelete", "Insufficient 'delete' privilege to delete the entry 'cn=" + hg + ",", true,
				func() error { return c.HostGroupDelete(hg) }},
			{"ServiceAdd", "Insufficient 'add' privilege to add the entry 'krbprincipalname=" + newSvc + ",", true,
				func() error { _, err := c.ServiceAdd(newSvc, true); return err }},
			{"ServiceDelete", "Insufficient 'delete' privilege to delete the entry 'krbprincipalname=" + svc + ",", true,
				func() error { return c.ServiceDelete(svc) }},
			{"HBACRuleAdd", "Insufficient 'add' privilege to add the entry 'ipaUniqueID=", true,
				func() error { _, err := c.HBACRuleAdd(&ipa.HBACRule{Name: newHBAC}); return err }},
			{"HBACRuleEnable", "Insufficient 'write' privilege to the 'ipaEnabledFlag' attribute of entry 'ipauniqueid=", false,
				func() error { return c.HBACRuleEnable(hbac.Name) }},
			{"HBACRuleDisable", "Insufficient 'write' privilege to the 'ipaEnabledFlag' attribute of entry 'ipauniqueid=", false,
				func() error { return c.HBACRuleDisable(hbacOn.Name) }},
			{"HBACRuleDelete", "Insufficient 'delete' privilege to delete the entry 'ipaUniqueID=", true,
				func() error { return c.HBACRuleDelete(hbacGone.Name) }},
			{"SudoRuleAdd", "Insufficient 'add' privilege to add the entry 'ipaUniqueID=", true,
				func() error { _, err := c.SudoRuleAdd(&ipa.SudoRule{Name: newSudo}); return err }},
			{"SudoRuleDelete", "Insufficient 'delete' privilege to delete the entry 'ipaUniqueID=", true,
				func() error { return c.SudoRuleDelete(sudo) }},
			{"DNSZoneAdd", "Insufficient 'add' privilege to add the entry 'idnsname=" + newZoneName + ",", true,
				func() error { _, err := c.DNSZoneAdd(newZoneName, false); return err }},
			{"AutomemberAdd", "Insufficient 'add' privilege to add the entry 'cn=" + autoGroup + ",cn=group,cn=automember,", false,
				func() error { _, err := c.AutomemberAdd(ipa.AutomemberGroup, autoGroup, ""); return err }},
		}
		for _, w := range gated {
			err := w.call()
			logProbe(t, ver, w.name, err)
			want := "ipa: error 2100 - Insufficient access: not allowed to perform this operation"
			if !w.gate || ldapACIRelease(ver) {
				want = "ipa: error 2100 - Insufficient access: " + w.ldap
			}
			if _, bare := err.(*ipa.IpaError); !bare || !errors.Is(err, ipa.ErrACI) || !strings.HasPrefix(err.Error(), want) {
				t.Errorf("%s: %v, want %s…", w.name, err, want)
			}
		}

		// Not gated: no keytab to remove comes first (Q157), on every release.
		wantCode(t, "HostDisable", c.HostDisable(host), ipa.CodeAlreadyInactive)
		wantCode(t, "ServiceDisable", c.ServiceDisable(svc), ipa.CodeAlreadyInactive)
		// Q171: zones are hidden from a plain user; ipatest does not model it.
		_, err = c.DNSRecordAdd(zone, "www", "A", "192.0.2.1")
		if b.name == "ipatest" {
			if err != nil {
				t.Errorf("ipatest dnsrecord_add: %v", err)
			}
		} else {
			wantIs(t, err, ipa.ErrNotFound)
		}

		// Self-service. Q172: 4.13.4 refuses an own passkey; ipatest does not model it.
		err = c.UserAddPasskey(uid, testPasskey)
		switch {
		case !serverAtLeast(ver, 4, 11):
		case b.name != "ipatest" && !ldapACIRelease(ver):
			wantIs(t, err, ipa.ErrACI)
		case err != nil:
			t.Errorf("own passkey: %v", err)
		}
		own, err := c.UserShow(uid)
		if err != nil {
			t.Fatal(err)
		}
		// Q174: only the self-service attributes of the own entry are writable;
		// the typed UserMod sends the whole record.
		own.First = "Self"
		_, err = c.UserMod(own)
		logProbe(t, ver, "own UserMod", err)
		wantIs(t, err, ipa.ErrACI)
		_, err = c.RPC("user_mod", []string{uid}, ipa.Options{"mail": []string{"self@example.test"}})
		logProbe(t, ver, "own user_mod mail", err)
		wantIs(t, err, ipa.ErrACI)
		_, err = c.RPC("user_mod", []string{uid}, ipa.Options{"title": "self"})
		logProbe(t, ver, "own user_mod title", err)
		if err != nil {
			t.Errorf("own user_mod title: %v", err)
		}
		if tok, err := c.AddOTPToken(nil); err != nil {
			t.Errorf("own OTP token: %v", err)
		} else {
			t.Cleanup(func() { _ = b.admin.RemoveOTPToken(tok.UUID) })
		}
		// The global minimum life (1 hour) would refuse the change as too soon.
		pol := newGroup(t, b)
		mustRPC(t, b.admin, "group_add_member", []string{pol}, ipa.Options{"user": []string{uid}})
		mustRPC(t, b.admin, "pwpolicy_add", []string{pol}, ipa.Options{"cospriority": newPriority(t), "krbminpwdlife": 0})
		t.Cleanup(func() { _, _ = b.admin.RPC("pwpolicy_del", []string{pol}, nil) })
		if err := c.ChangePassword(uid, goodPW, "Another-Passw0rd-2", ""); err != nil {
			t.Errorf("own password: %v", err)
		}
	})
}

// newPriority is a cospriority no other test is likely to hold.
func newPriority(t *testing.T) int {
	n, err := strconv.ParseUint(randHex(t, 3), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	return 1000 + int(n%1000000)
}

// ldapACIRelease mirrors ipatest: 4.12.2 answers from the LDAP ACIs, the
// 4.9.13 image and 4.13.4 from the API gate.
func ldapACIRelease(ver string) bool {
	var ma, mi, pa int
	_, _ = fmt.Sscanf(ver, "%d.%d.%d", &ma, &mi, &pa)
	return ma == 4 && mi >= 10 && (mi < 13 || mi == 13 && pa < 4)
}

// TestContractPrivilegeNames checks that the privileges ipatest's
// GrantPrivilege acts on exist under these names.
func TestContractPrivilegeNames(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		if b.name == "ipatest" {
			t.Skip("ipatest seeds User Administrators only")
		}
		for _, p := range []string{"User Administrators", "Stage User Administrators", "Stage User Provisioning",
			"Group Administrators", "Modify Group membership", "Host Administrators", "Host Group Administrators",
			"Service Administrators", "HBAC Administrator", "Sudo Administrator", "DNS Administrators",
			"Password Policy Readers", "Password Policy Administrator", "Certificate Administrators", "RBAC Readers"} {
			if _, err := b.admin.PrivilegeShow(p); err != nil {
				t.Errorf("%s: %v", p, err)
			}
		}
	})
}

func logProbe(t *testing.T, ver, name string, err error) {
	t.Helper()
	var ie *ipa.IpaError
	switch {
	case err == nil:
		t.Logf("PERMPROBE %s %s: ok", ver, name)
	case errors.As(err, &ie):
		t.Logf("PERMPROBE %s %s: %d %s", ver, name, ie.Code, ie.Message)
	default:
		t.Logf("PERMPROBE %s %s: %v", ver, name, err)
	}
}
