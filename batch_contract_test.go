// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/neverlless/goipa"
)

// X5
func TestContractBatch(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, "Secret123!x")
		rs, err := b.admin.Batch(context.Background(),
			ipa.BatchCall{Method: "user_show", Args: []string{uid}},
			ipa.BatchCall{Method: "user_show", Args: []string{"gtmissing" + randHex(t, 4)}})
		if err != nil || len(rs) != 2 {
			t.Fatalf("%v, %v", rs, err)
		}
		if rs[0].Result == nil || rs[0].Err != nil {
			t.Errorf("results[0] = %+v", rs[0])
		}
		if e, ok := rs[1].Err.(*ipa.IpaError); !ok || e.Code != ipa.CodeNotFound || e.Name != "NotFound" {
			t.Errorf("results[1] = %+v, err %+v", rs[1], rs[1].Err)
		}
	})
}

func TestContractBatchDecode(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, "Secret123!x")
		gn := "gt" + randHex(t, 4)
		if _, err := b.admin.GroupAdd(&ipa.Group{Name: gn}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.admin.GroupDelete(gn) })
		rs, err := b.admin.Batch(context.Background(),
			ipa.BatchCall{Method: "user_show", Args: []string{uid}, Options: ipa.Options{"all": true, "no_members": false}},
			ipa.BatchCall{Method: "group_find", Args: []string{""}, Options: ipa.Options{"all": true, "no_members": false, "cn": gn}},
			ipa.BatchCall{Method: "otptoken_find", Args: []string{""}, Options: ipa.Options{"ipatokenowner": uid, "all": true}})
		if err != nil || len(rs) != 3 {
			t.Fatalf("%v, %v", rs, err)
		}
		u, err := ipa.DecodeUser(rs[0])
		wu, werr := b.admin.UserShow(uid)
		if err != nil || werr != nil || !reflect.DeepEqual(u, wu) {
			t.Errorf("user %+v, %v; want %+v, %v", u, err, wu, werr)
		}
		g, err := ipa.DecodeGroups(rs[1])
		wg, werr := b.admin.GroupFind(ipa.Options{"cn": gn})
		if err != nil || werr != nil || len(g) != 1 || !reflect.DeepEqual(g, wg) {
			t.Errorf("groups %+v, %v; want %+v, %v", g, err, wg, werr)
		}
		o, err := ipa.DecodeOTPTokens(rs[2])
		wo, werr := b.admin.FetchOTPTokens(uid)
		if err != nil || werr != nil || !reflect.DeepEqual(o, wo) {
			t.Errorf("tokens %+v, %v; want %+v, %v", o, err, wo, werr)
		}
	})
}
