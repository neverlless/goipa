// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// V9
func TestContractHBACRuleFind(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		all, err := b.admin.HBACRuleFind(ipa.Options{"cn": "allow_all"})
		if err != nil || len(all) != 1 || !all[0].Enabled || all[0].UserCategory != "all" {
			t.Fatalf("allow_all = %+v, %v", all, err)
		}
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		r := "gr" + randHex(t, 4)
		if _, err := b.admin.RPC("hbacrule_add", []string{r}, ipa.Options{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = b.admin.RPC("hbacrule_del", []string{r}, nil) })
		if _, err := b.admin.RPC("hbacrule_add_user", []string{r}, ipa.Options{"user": []string{uid}}); err != nil {
			t.Fatal(err)
		}
		got, err := b.admin.HBACRuleFind(ipa.Options{"cn": r})
		if err != nil || len(got) != 1 || !got[0].Enabled || !reflect.DeepEqual(got[0].Users, []string{uid}) {
			t.Fatalf("rule = %+v, %v", got, err)
		}
		raw, err := b.admin.RPC("hbacrule_find", []string{""}, ipa.Options{"cn": r, "all": true})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ipaenabledflag raw: %s", gjson.GetBytes(raw.Result.Data, "0.ipaenabledflag").Raw)
	})
}

// V10
func TestContractSudoRuleFind(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		r := "gs" + randHex(t, 4)
		if _, err := b.admin.RPC("sudorule_add", []string{r}, ipa.Options{"sudoorder": 5}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = b.admin.RPC("sudorule_del", []string{r}, nil) })
		if _, err := b.admin.RPC("sudorule_add_user", []string{r}, ipa.Options{"user": []string{uid}}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.RPC("sudorule_add_option", []string{r}, ipa.Options{"ipasudoopt": "!authenticate"}); err != nil {
			t.Fatal(err)
		}
		got, err := b.admin.SudoRuleFind(ipa.Options{"cn": r})
		if err != nil || len(got) != 1 {
			t.Fatalf("rule = %+v, %v", got, err)
		}
		g := got[0]
		if !g.Enabled || g.Order != 5 || !reflect.DeepEqual(g.Users, []string{uid}) || !reflect.DeepEqual(g.Options, []string{"!authenticate"}) {
			t.Errorf("rule = %+v", g)
		}
	})
}
