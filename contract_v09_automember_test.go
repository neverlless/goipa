// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
)

// newRule adds a group rule for a new group and deletes it when the test ends.
func newRule(t *testing.T, b backend) string {
	t.Helper()
	cn := newGroup(t, b)
	if _, err := b.admin.AutomemberAdd(ipa.AutomemberGroup, cn, "goipa rule"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.admin.AutomemberDelete(ipa.AutomemberGroup, cn) })
	return cn
}

func addUser(t *testing.T, b backend, uid, title string) {
	t.Helper()
	t.Cleanup(func() { _ = b.admin.UserDelete(false, false, uid) })
	o := ipa.Options{"givenname": "Go", "sn": "Test"}
	if title != "" {
		o["title"] = title // UserAdd does not send title
	}
	mustRPC(t, b.admin, "user_add", []string{uid}, o)
}

func inGroup(t *testing.T, b backend, uid, cn string) bool {
	t.Helper()
	g, err := b.admin.GroupShow(cn)
	if err != nil {
		t.Fatal(err)
	}
	return slices.Contains(g.Users, uid)
}

// TestContractAutomemberRule pins Q110, Q111 and Q112: conditions are stored
// as key=regex, a new user matching an inclusive and no exclusive condition
// lands in the group.
func TestContractAutomemberRule(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newRule(t, b)
		prefix := "goipa" + randHex(t, 3)
		if _, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, cn, "uid", []string{"^" + prefix}, nil); err != nil {
			t.Fatal(err)
		}
		r, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, cn, "title", nil, []string{"^x"})
		if err != nil {
			t.Fatal(err)
		}
		want := &ipa.AutomemberRule{Name: cn, Type: ipa.AutomemberGroup, Description: "goipa rule",
			Inclusive: []ipa.AutomemberCondition{{Key: "uid", Regex: "^" + prefix}},
			Exclusive: []ipa.AutomemberCondition{{Key: "title", Regex: "^x"}}}
		if !reflect.DeepEqual(r, want) {
			t.Fatalf("AddCondition = %+v, want %+v", r, want)
		}
		if got, err := b.admin.AutomemberShow(ipa.AutomemberGroup, cn); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("Show = %+v, %v", got, err)
		}
		// Adding a condition the rule has changes nothing; the full rule still comes back.
		if got, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, cn, "uid", []string{"^" + prefix}, nil); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("AddCondition again = %+v, %v", got, err)
		}
		rules, err := b.admin.AutomemberFind(ipa.AutomemberGroup, nil)
		if err != nil || !slices.ContainsFunc(rules, func(r *ipa.AutomemberRule) bool { return reflect.DeepEqual(r, want) }) {
			t.Fatalf("Find = %v, %v", rules, err)
		}

		addUser(t, b, prefix+"a", "")
		addUser(t, b, prefix+"b", "xboss")
		if !inGroup(t, b, prefix+"a", cn) {
			t.Error("matching user not in the group")
		}
		if inGroup(t, b, prefix+"b", cn) {
			t.Error("excluded user in the group")
		}
	})
}

// TestContractAutomemberRebuild pins Q112: rebuild applies a rule to users
// created before it.
func TestContractAutomemberRebuild(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := "goipa" + randHex(t, 3)
		addUser(t, b, uid, "")
		cn := newRule(t, b)
		if _, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, cn, "uid", []string{"^" + uid + "$"}, nil); err != nil {
			t.Fatal(err)
		}
		if inGroup(t, b, uid, cn) {
			t.Fatal("user in the group before rebuild")
		}
		if err := b.admin.AutomemberRebuild(ipa.AutomemberGroup); err != nil {
			t.Fatal(err)
		}
		if !inGroup(t, b, uid, cn) {
			t.Error("user not in the group after rebuild")
		}
	})
}

// TestContractAutomemberRemoveCondition pins Q111: a condition the rule lacks
// comes back as a failure next to the updated rule.
func TestContractAutomemberRemoveCondition(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := newRule(t, b)
		if _, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, cn, "uid", []string{"^a", "^b"}, nil); err != nil {
			t.Fatal(err)
		}
		r, err := b.admin.AutomemberRemoveCondition(ipa.AutomemberGroup, cn, "uid", []string{"^a", "^nothere"}, nil)
		var me *ipa.MemberError
		if !errors.As(err, &me) || len(me.Failures) != 1 || me.Failures[0].Name != "uid=^nothere" || me.Failures[0].Type != "automemberinclusiveregex" {
			t.Fatalf("err = %v, want one failure for uid=^nothere", err)
		}
		if r == nil || r.Name != cn || !reflect.DeepEqual(r.Inclusive, []ipa.AutomemberCondition{{Key: "uid", Regex: "^b"}}) {
			t.Fatalf("rule = %+v", r)
		}
		r, err = b.admin.AutomemberRemoveCondition(ipa.AutomemberGroup, cn, "uid", []string{"^nothere"}, nil)
		if !errors.As(err, &me) || r == nil || r.Description != "goipa rule" || len(r.Inclusive) != 1 {
			t.Fatalf("nothing removed: %+v, %v", r, err)
		}
	})
}

// TestContractAutomemberMissing pins Q110, Q111 and Q114.
func TestContractAutomemberMissing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		missing := "gm" + randHex(t, 4)
		_, err := b.admin.AutomemberAddCondition(ipa.AutomemberGroup, missing, "uid", []string{"^x"}, nil)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = b.admin.AutomemberRemoveCondition(ipa.AutomemberGroup, missing, "uid", []string{"^x"}, nil)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = b.admin.AutomemberShow(ipa.AutomemberGroup, missing)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = b.admin.AutomemberAdd(ipa.AutomemberGroup, missing, "")
		wantIs(t, err, ipa.ErrNotFound) // no such group

		cn := newRule(t, b)
		_, err = b.admin.AutomemberAdd(ipa.AutomemberGroup, cn, "")
		wantCode(t, "duplicate add", err, ipa.CodeDuplicateEntry)
		_, err = b.admin.AutomemberShow(ipa.AutomemberHostGroup, cn)
		wantIs(t, err, ipa.ErrNotFound)
		// The rule named before the missing one is deleted all the same.
		wantIs(t, b.admin.AutomemberDelete(ipa.AutomemberGroup, cn, missing), ipa.ErrNotFound)
		_, err = b.admin.AutomemberShow(ipa.AutomemberGroup, cn)
		wantIs(t, err, ipa.ErrNotFound)
		_, err = b.rawAdmin().RPC("automember_show", []string{cn}, ipa.Options{"type": "bogus"})
		wantCode(t, "bad type", err, ipa.CodeValidation)
	})
}

// TestContractAutomemberDefaultGroup pins Q113.
func TestContractAutomemberDefaultGroup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		orig, err := b.admin.AutomemberDefaultGroup(ipa.AutomemberGroup)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if orig == "" {
				_ = b.admin.AutomemberRemoveDefaultGroup(ipa.AutomemberGroup)
			} else {
				_ = b.admin.AutomemberSetDefaultGroup(ipa.AutomemberGroup, orig)
			}
		})
		if orig != "" {
			if err := b.admin.AutomemberRemoveDefaultGroup(ipa.AutomemberGroup); err != nil {
				t.Fatal(err)
			}
		}
		wantIs(t, b.admin.AutomemberRemoveDefaultGroup(ipa.AutomemberGroup), ipa.ErrNotFound)
		wantIs(t, b.admin.AutomemberSetDefaultGroup(ipa.AutomemberGroup, "gm"+randHex(t, 4)), ipa.ErrNotFound)

		cn := newGroup(t, b)
		if err := b.admin.AutomemberSetDefaultGroup(ipa.AutomemberGroup, cn); err != nil {
			t.Fatal(err)
		}
		wantIs(t, b.admin.AutomemberSetDefaultGroup(ipa.AutomemberGroup, cn), ipa.ErrEmptyModlist)
		if got, err := b.admin.AutomemberDefaultGroup(ipa.AutomemberGroup); err != nil || got != cn {
			t.Fatalf("DefaultGroup = %q, %v, want %q", got, err, cn)
		}
		uid := "goipa" + randHex(t, 3)
		addUser(t, b, uid, "")
		if !inGroup(t, b, uid, cn) {
			t.Error("user matching no rule not in the default group")
		}
		if err := b.admin.AutomemberRemoveDefaultGroup(ipa.AutomemberGroup); err != nil {
			t.Fatal(err)
		}
		if got, err := b.admin.AutomemberDefaultGroup(ipa.AutomemberGroup); err != nil || got != "" {
			t.Fatalf("DefaultGroup after remove = %q, %v", got, err)
		}
	})
}

// TestContractAutomemberHostGroup pins Q110: a hostgroup rule's lifecycle.
func TestContractAutomemberHostGroup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		cn := "gh" + randHex(t, 4)
		_, err := b.admin.AutomemberAdd(ipa.AutomemberHostGroup, cn, "")
		wantIs(t, err, ipa.ErrNotFound)
		wantIs(t, b.admin.AutomemberSetDefaultGroup(ipa.AutomemberHostGroup, cn), ipa.ErrNotFound)
		mustRPC(t, b.admin, "hostgroup_add", []string{cn}, nil)
		t.Cleanup(func() { _, _ = b.admin.RPC("hostgroup_del", []string{cn}, nil) })
		if _, err := b.admin.AutomemberAdd(ipa.AutomemberHostGroup, cn, ""); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.AutomemberDelete(ipa.AutomemberHostGroup, cn) })
		r, err := b.admin.AutomemberAddCondition(ipa.AutomemberHostGroup, cn, "fqdn", []string{"^web"}, nil)
		want := &ipa.AutomemberRule{Name: cn, Type: ipa.AutomemberHostGroup, Inclusive: []ipa.AutomemberCondition{{Key: "fqdn", Regex: "^web"}}}
		if err != nil || !reflect.DeepEqual(r, want) {
			t.Fatalf("AddCondition = %+v, %v", r, err)
		}
		rules, err := b.admin.AutomemberFind(ipa.AutomemberHostGroup, nil)
		if err != nil || !slices.ContainsFunc(rules, func(r *ipa.AutomemberRule) bool { return reflect.DeepEqual(r, want) }) {
			t.Fatalf("Find = %v, %v", rules, err)
		}
		if err := b.admin.AutomemberRebuild(ipa.AutomemberHostGroup); err != nil {
			t.Fatal(err)
		}
		if got, err := b.admin.AutomemberDefaultGroup(ipa.AutomemberHostGroup); err != nil || got != "" {
			t.Fatalf("hostgroup DefaultGroup = %q, %v", got, err)
		}
		if err := b.admin.AutomemberDelete(ipa.AutomemberHostGroup, cn); err != nil {
			t.Fatal(err)
		}
		_, err = b.admin.AutomemberShow(ipa.AutomemberHostGroup, cn)
		wantIs(t, err, ipa.ErrNotFound)
	})
}
