// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
)

// TestContractHostGroupMixedCaseReferences pins Q51: a host group named in
// another case resolves, and is reported lower-cased.
func TestContractHostGroupMixedCaseReferences(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newHostGroup(t, b)
		mixed := strings.ToUpper(cn)
		want := []string{cn}

		rule := newHBACRule(t, b, ipa.HBACRule{})
		hr, err := b.admin.HBACRuleAddHost(rule.Name, nil, []string{mixed})
		if err != nil || !slices.Equal(hr.HostGroups, want) {
			t.Errorf("hbac: %v, %v; want %v", hr, err, want)
		}

		sr := newSudoRule(t, b)
		su, err := b.admin.SudoRuleAddHost(sr, nil, []string{mixed})
		if err != nil || !slices.Equal(su.HostGroups, want) {
			t.Errorf("sudo: %v, %v; want %v", su, err, want)
		}

		principal, _ := newService(t, b)
		svc, err := b.admin.ServiceAllowRetrieveKeytab(principal, ipa.KeytabAccess{HostGroups: []string{mixed}})
		if err != nil || !slices.Equal(svc.KeytabRetrieve.HostGroups, want) {
			t.Errorf("keytab: %v, %v; want %v", svc, err, want)
		}

		parent := newHostGroup(t, b)
		g, err := b.admin.HostGroupAddMember(parent, nil, []string{mixed})
		if err != nil || !slices.Equal(g.HostGroups, want) {
			t.Errorf("nested: %v, %v; want %v", g, err, want)
		}

		hr, err = b.admin.HBACRuleRemoveHost(rule.Name, nil, []string{mixed})
		if err != nil || len(hr.HostGroups) != 0 {
			t.Errorf("hbac remove: %v, %v", hr, err)
		}
	})
}

// TestContractAutomemberHostGroupMixedCase pins Q51 for automember rules: the
// target host group resolves in any case.
func TestContractAutomemberHostGroupMixedCase(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newHostGroup(t, b)
		t.Cleanup(func() { _ = b.admin.AutomemberDelete(ipa.AutomemberHostGroup, cn) })
		r, err := b.admin.AutomemberAdd(ipa.AutomemberHostGroup, strings.ToUpper(cn), "goipa rule")
		if err != nil {
			t.Fatal(err)
		}
		if r.Name != cn {
			t.Errorf("name = %q, want %q", r.Name, cn)
		}
		if _, err := b.admin.AutomemberShow(ipa.AutomemberHostGroup, strings.ToUpper(cn)); err != nil {
			t.Errorf("show: %v", err)
		}
	})
}
