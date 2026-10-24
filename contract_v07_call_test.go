// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"testing"
	"time"

	"github.com/neverlless/goipa"
)

// X1
func TestContractCallEntry(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, "Secret123!x")
		e, _, err := ipa.Call[ipa.Entry](context.Background(), b.admin, "user_show", []string{uid}, ipa.Options{"all": true})
		if err != nil {
			t.Fatal(err)
		}
		if e.Str("uid") != uid || e.Bool("nsaccountlock") {
			t.Errorf("uid %q, locked %v", e.Str("uid"), e.Bool("nsaccountlock"))
		}
		if e.Time("krbpasswordexpiration").Before(time.Now().Add(-24 * time.Hour)) {
			t.Errorf("krbpasswordexpiration = %v", e.Time("krbpasswordexpiration"))
		}
	})
}

// X2
func TestContractFindTruncated(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		prefix := "gtp" + randHex(t, 4)
		for i := 0; i < 2; i++ {
			uid := newUID(t, b)
			u := &ipa.User{Username: uid, First: prefix, Last: "Test"}
			if _, err := b.admin.UserAdd(u, false); err != nil {
				t.Fatal(err)
			}
		}
		es, err := ipa.FindEntries(context.Background(), b.admin, "user_find", prefix, nil, 1)
		if err != ipa.ErrTruncated || len(es) != 1 {
			t.Fatalf("%d entries, %v", len(es), err)
		}
	})
}
