// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
)

// newHostGroup adds a host group and deletes it when the test ends.
func newHostGroup(t *testing.T, b backend) string {
	t.Helper()
	cn := "hg" + randHex(t, 4)
	if _, err := b.admin.HostGroupAdd(&ipa.HostGroup{Name: cn}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.HostGroupDelete(cn) })
	return cn
}

func TestContractHostGroupLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := "hg" + randHex(t, 4)
		t.Cleanup(func() { _ = b.admin.HostGroupDelete(cn) })
		added, err := b.admin.HostGroupAdd(&ipa.HostGroup{Name: cn, Description: "contract"})
		if err != nil {
			t.Fatal(err)
		}
		if added.Name != cn || added.Description != "contract" {
			t.Errorf("added = %+v", added)
		}
		g, err := b.admin.HostGroupShow(cn)
		if err != nil {
			t.Fatal(err)
		}
		if g.Name != cn || g.Description != "contract" || len(g.Hosts) != 0 {
			t.Errorf("shown = %+v", g)
		}
		found, err := b.admin.HostGroupFind(ipa.Options{"cn": cn})
		if err != nil || len(found) != 1 || found[0].Name != cn {
			t.Fatalf("find = %v, err = %v", found, err)
		}
		if err := b.admin.HostGroupDelete(cn); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.HostGroupShow(cn)
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != ipa.CodeNotFound {
			t.Fatalf("show after delete: %v, want bare 4001", err)
		}
	})
}

// TestContractHostGroupMembers pins Q50 and Q51.
func TestContractHostGroupMembers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		parent, child, fqdn := newHostGroup(t, b), newHostGroup(t, b), serverHost(t, b)
		g, err := b.admin.HostGroupAddMember(parent, []string{fqdn}, []string{child})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(g.Hosts, []string{fqdn}) || !slices.Equal(g.HostGroups, []string{child}) {
			t.Errorf("after add: hosts %v, hostgroups %v", g.Hosts, g.HostGroups)
		}
		c, err := b.admin.HostGroupShow(child)
		if err != nil || !slices.Equal(c.MemberOf, []string{parent}) {
			t.Errorf("child memberof = %v, err = %v", c, err)
		}
		h, err := b.admin.HostShow(fqdn)
		if err != nil || !slices.Contains(h.HostGroups, parent) {
			t.Errorf("host hostgroups = %v, err = %v", h, err)
		}

		// Move the host into the nested group: it becomes an indirect member.
		if _, err := b.admin.HostGroupRemoveMember(parent, []string{fqdn}, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.HostGroupAddMember(child, []string{fqdn}, nil); err != nil {
			t.Fatal(err)
		}
		g, err = b.admin.HostGroupShow(parent)
		if err != nil || len(g.Hosts) != 0 || !slices.Equal(g.IndirectHosts, []string{fqdn}) {
			t.Errorf("parent = %+v, err = %v", g, err)
		}
		h, err = b.admin.HostShow(fqdn)
		if err != nil || !slices.Contains(h.HostGroups, child) || !slices.Contains(h.IndirectHostGroups, parent) || slices.Contains(h.HostGroups, parent) {
			t.Errorf("host = %+v, err = %v", h, err)
		}

		if _, err := b.admin.HostGroupRemoveMember(child, []string{fqdn}, nil); err != nil {
			t.Fatal(err)
		}
		g, err = b.admin.HostGroupRemoveMember(parent, nil, []string{child})
		if err != nil || len(g.Hosts)+len(g.HostGroups)+len(g.IndirectHosts) != 0 {
			t.Errorf("after remove = %+v, err = %v", g, err)
		}
	})
}

func TestContractHostGroupMemberMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newHostGroup(t, b)
		missing := "nohost" + randHex(t, 4) + ".invalid.test"
		g, err := b.admin.HostGroupAddMember(cn, []string{missing}, nil)
		var me *ipa.MemberError
		if !errors.As(err, &me) || g == nil || g.Name != cn {
			t.Fatalf("g = %v, err = %v, want the group and *MemberError", g, err)
		}
		if len(me.Failures) != 1 || me.Failures[0].Type != "host" || me.Failures[0].Name != missing {
			t.Errorf("failures = %+v", me.Failures)
		}
	})
}

func TestContractHostGroupManagers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn, uid := newHostGroup(t, b), newUserWithPassword(t, b, goodPW)
		g, err := b.admin.HostGroupAddMemberManager(cn, []string{uid}, nil)
		if err != nil || !slices.Equal(g.ManagerUsers, []string{uid}) {
			t.Fatalf("g = %v, err = %v", g, err)
		}
		g, err = b.admin.HostGroupRemoveMemberManager(cn, []string{uid}, nil)
		if err != nil || len(g.ManagerUsers) != 0 {
			t.Fatalf("after remove g = %v, err = %v", g, err)
		}
	})
}

// TestContractHostGroupMixedCase pins Q51's case rule: the name keeps its
// case, and find's criteria match it case-insensitively.
func TestContractHostGroupMixedCase(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := "GoipaMixed" + randHex(t, 4)
		t.Cleanup(func() { _ = b.admin.HostGroupDelete(cn) })
		added, err := b.admin.HostGroupAdd(&ipa.HostGroup{Name: cn})
		if err != nil {
			t.Fatal(err)
		}
		g, err := b.admin.HostGroupShow(cn)
		if err != nil {
			t.Fatal(err)
		}
		if added.Name != cn || g.Name != cn {
			t.Errorf("added %q, shown %q, want %q", added.Name, g.Name, cn)
		}
		res := mustRPC(t, b.admin, "hostgroup_find", []string{strings.ToLower(cn)}, nil)
		if res.Result.Count != 1 {
			t.Errorf("find %q: %d matches, want 1", strings.ToLower(cn), res.Result.Count)
		}
	})
}
