// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	"github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// Contract tests for the FreeIPA behaviours v0.5 relies on (V1-V13 in the
// plan). Seeding goes through the admin client only, so they also run against
// a real server.

// newStageUID returns an unused uid and deletes the stage and the active
// user of that name when the test ends.
func newStageUID(t *testing.T, b backend) string {
	uid := "gs" + randHex(t, 4)
	t.Cleanup(func() {
		_ = b.admin.StageUserDelete(uid)
		_ = b.admin.UserDelete(false, false, uid)
	})
	return uid
}

// V1, V2, V3
func TestContractStageUserLifecycle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newStageUID(t, b)
		u, err := b.admin.StageUserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test", Category: "staff", Email: "x@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if u.Username != uid || !u.Locked { // V2
			t.Errorf("added = %q locked %v", u.Username, u.Locked)
		}
		if u.Uid != "-1" || u.Gid != "-1" { // DNA magic value until activation
			t.Errorf("stage uidnumber %q gidnumber %q, want -1", u.Uid, u.Gid)
		}
		if got, err := b.admin.StageUserShow(uid); err != nil || got.Category != "staff" {
			t.Fatalf("show = %+v, %v", got, err)
		}
		if got, err := b.admin.StageUserMod(&ipa.User{Username: uid, First: "Go", Last: "Test", Category: "c2", Email: "x@example.com"}); err != nil || got.Category != "c2" {
			t.Fatalf("mod = %+v, %v", got, err)
		}
		same := &ipa.User{Username: uid, First: "Go", Last: "Test", Category: "c2", Email: "x@example.com"}
		if got, err := b.admin.StageUserMod(same); err != nil || got != same {
			t.Fatalf("unchanged mod = %p, %v, want the input", got, err)
		}
		found, err := b.admin.StageUserFind(ipa.Options{"uid": uid})
		if err != nil || len(found) != 1 || found[0].Category != "c2" {
			t.Fatalf("find = %v, %v", found, err)
		}

		uid2 := newStageUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid2, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := b.admin.StageUserAdd(&ipa.User{Username: uid2, First: "Go", Last: "Test"}); err != nil {
			t.Fatal(err) // stageuser_add does not look at active users
		}
		_, err = b.admin.StageUserActivate(uid2)
		var ie *ipa.IpaError
		if !errors.Is(err, ipa.ErrDuplicateEntry) || !errors.As(err, &ie) || ie != err { // V3
			t.Errorf("activate over active = %v (%T), want bare duplicate", err, err)
		}
		if _, err := b.admin.StageUserShow(uid2); err != nil {
			t.Errorf("stage entry gone after failed activate: %v", err)
		}

		act, err := b.admin.StageUserActivate(uid)
		if err != nil || act.Username != uid || act.Locked || act.Uid == "" || act.Uid == "-1" {
			t.Fatalf("activate = %+v, %v", act, err)
		}
		if _, err := b.admin.UserShow(uid); err != nil {
			t.Errorf("UserShow: %v", err)
		}
		if _, err := b.admin.StageUserShow(uid); !errors.Is(err, ipa.ErrNotFound) {
			t.Errorf("StageUserShow after activate = %v, want ErrNotFound", err)
		}
	})
}

// V1
func TestContractStageFindUserclassNeedsAll(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newStageUID(t, b)
		if _, err := b.admin.StageUserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test", Category: "staff"}); err != nil {
			t.Fatal(err)
		}
		res := mustRPC(t, b.admin, "stageuser_find", []string{""}, ipa.Options{"uid": uid})
		if gjson.GetBytes(res.Result.Data, "0.userclass").Exists() {
			t.Errorf("userclass returned without all: %s", res.Result.Data)
		}
		res = mustRPC(t, b.admin, "stageuser_find", []string{""}, ipa.Options{"uid": uid, "all": true})
		if !gjson.GetBytes(res.Result.Data, "0.userclass").Exists() {
			t.Errorf("no userclass with all: %s", res.Result.Data)
		}
	})
}

// V3
func TestContractStageActivateSummary(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newStageUID(t, b)
		if _, err := b.admin.StageUserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}); err != nil {
			t.Fatal(err)
		}
		res := mustRPC(t, b.admin, "stageuser_activate", []string{uid}, nil)
		if want := "Stage user " + uid + " activated"; res.Result.Summary != want {
			t.Errorf("summary = %q, want %q", res.Result.Summary, want)
		}
	})
}
