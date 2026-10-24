// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// enableSubIDs turns sub-IDs on for a real server installed without --subid
// (FreeIPA 4.10+ keeps SubID:Disable in ipaconfigstring) and restores the
// setting afterwards. ipatest does not model config; 4.9 has no such value.
func enableSubIDs(t *testing.T, b backend) {
	t.Helper()
	if b.name == "ipatest" {
		return
	}
	res, err := b.admin.RPC("config_show", nil, ipa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var orig []string
	for _, v := range gjson.ParseBytes(res.Result.Data).Get("ipaconfigstring").Array() {
		orig = append(orig, v.String())
	}
	if !slices.Contains(orig, "SubID:Disable") {
		return
	}
	set := func(v []string) error {
		_, err := b.admin.RPC("config_mod", nil, ipa.Options{"ipaconfigstring": v})
		return err
	}
	rest := slices.DeleteFunc(slices.Clone(orig), func(s string) bool { return s == "SubID:Disable" })
	if err := set(rest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := set(orig); err != nil {
			t.Errorf("restore ipaconfigstring %v: %v", orig, err)
		}
	})
}

// V8
func TestContractSubIDGenerate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		enableSubIDs(t, b)
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		sub, err := b.admin.SubIDGenerate(uid)
		if err != nil {
			t.Fatal(err)
		}
		if sub.Owner != uid || sub.UIDCount != 65536 || sub.UIDStart <= 0 || sub.ID == "" {
			t.Errorf("sub = %+v", sub)
		}
		_, err = b.admin.SubIDGenerate(uid)
		var ie *ipa.IpaError
		if !errors.Is(err, ipa.ErrDuplicateEntry) || !errors.As(err, &ie) || ie != err {
			t.Errorf("second generate = %v (%T), want bare duplicate", err, err)
		}
		found, err := b.admin.SubIDFind(ipa.Options{"ipaowner": uid})
		if err != nil || len(found) != 1 || found[0].ID != sub.ID {
			t.Errorf("find = %+v, %v", found, err)
		}
	})
}

func TestContractSubIDGenerate_UnknownOwner(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		enableSubIDs(t, b)
		if _, err := b.admin.SubIDGenerate("nosuch" + randHex(t, 4)); !errors.Is(err, ipa.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}
