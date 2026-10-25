// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
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
