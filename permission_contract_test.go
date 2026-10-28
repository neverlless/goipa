// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	"github.com/neverlless/goipa"
)

// TestContractPlainUserWrites runs the typed writes as a user outside admins
// with no roles, and the self-service calls that must keep working.
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
		writes := []struct {
			name string
			call func() error
		}{
			{"UserAdd", func() error { _, err := c.UserAdd(user(newUser), false); return err }},
			{"UserMod", func() error { _, err := c.UserMod(otherRec); return err }},
			{"UserDelete", func() error { return c.UserDelete(false, false, victim) }},
			{"StageUserAdd", func() error { _, err := c.StageUserAdd(user(newStage)); return err }},
			{"StageUserAddWithPassword", func() error {
				_, err := c.StageUserAddWithPassword(user(newStagePW), goodPW)
				return err
			}},
			{"GroupAdd", func() error { _, err := c.GroupAdd(&ipa.Group{Name: newGroupName}); return err }},
			{"GroupMod", func() error { _, err := c.GroupMod(&ipa.Group{Name: group, Description: "changed"}); return err }},
			{"GroupDelete", func() error { return c.GroupDelete(gone) }},
			{"HostAdd", func() error { _, err := c.HostAdd(&ipa.Host{FQDN: newHost}, true, false); return err }},
			{"HostMod", func() error { _, err := c.HostMod(&ipa.Host{FQDN: host, Description: "changed"}); return err }},
			{"HostDisable", func() error { return c.HostDisable(host) }},
			{"HostDelete", func() error { return c.HostDelete(false, hostGone) }},
			{"HostGroupAdd", func() error { _, err := c.HostGroupAdd(&ipa.HostGroup{Name: newHG}); return err }},
			{"HostGroupDelete", func() error { return c.HostGroupDelete(hg) }},
			{"ServiceAdd", func() error { _, err := c.ServiceAdd(newSvc, true); return err }},
			{"ServiceDisable", func() error { return c.ServiceDisable(svc) }},
			{"ServiceDelete", func() error { return c.ServiceDelete(svc) }},
			{"HBACRuleAdd", func() error { _, err := c.HBACRuleAdd(&ipa.HBACRule{Name: newHBAC}); return err }},
			{"HBACRuleEnable", func() error { return c.HBACRuleEnable(hbac.Name) }},
			{"HBACRuleDelete", func() error { return c.HBACRuleDelete(hbacGone.Name) }},
			{"SudoRuleAdd", func() error { _, err := c.SudoRuleAdd(&ipa.SudoRule{Name: newSudo}); return err }},
			{"SudoRuleDelete", func() error { return c.SudoRuleDelete(sudo) }},
			{"DNSZoneAdd", func() error { _, err := c.DNSZoneAdd(newZoneName, false); return err }},
			{"DNSRecordAdd", func() error { _, err := c.DNSRecordAdd(zone, "www", "A", "192.0.2.1"); return err }},
			{"AutomemberAdd", func() error { _, err := c.AutomemberAdd(ipa.AutomemberGroup, autoGroup, ""); return err }},
		}
		for _, w := range writes {
			logProbe(t, ver, w.name, w.call())
		}

		self := []struct {
			name string
			call func() error
		}{
			{"own UserAddPasskey", func() error {
				if !serverAtLeast(ver, 4, 11) {
					return nil
				}
				return c.UserAddPasskey(uid, testPasskey)
			}},
			{"own AddOTPToken", func() error {
				tok, err := c.AddOTPToken(nil)
				if err == nil {
					t.Cleanup(func() { _ = b.admin.RemoveOTPToken(tok.UUID) })
				}
				return err
			}},
			{"own ChangePassword", func() error { return c.ChangePassword(uid, goodPW, "Another-Passw0rd-2", "") }},
		}
		for _, s := range self {
			err := s.call()
			logProbe(t, ver, s.name, err)
			if err != nil {
				t.Errorf("%s: %v", s.name, err)
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
