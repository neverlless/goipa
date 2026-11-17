// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"slices"
	"testing"

	ipa "github.com/neverlless/goipa"
)

// V12; pins Q200 to Q202.
func TestContractSelfService(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		res, err := b.admin.RPC("ping", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := b.admin.SelfServiceFind(nil)
		if err != nil {
			t.Fatal(err)
		}
		want := 5
		if serverAtLeast(res.Version, 4, 11) {
			want = 6
		}
		if len(rules) != want {
			t.Errorf("%d rules on %s, want %d", len(rules), res.Version, want)
		}
		r, err := b.admin.SelfServiceShow("User Self service")
		if err != nil || !slices.Contains(r.Attrs, "manager") || !slices.Equal(r.Permissions, []string{"write"}) {
			t.Errorf("show = %+v, %v", r, err)
		}
		byAttr, err := b.admin.SelfServiceFind(ipa.Options{"attrs": "manager"})
		if err != nil || len(byAttr) != 1 || byAttr[0].Name != "User Self service" {
			t.Errorf("find by attrs = %+v, %v", byAttr, err)
		}
		_, err = b.admin.SelfServiceShow("no such rule")
		wantIs(t, err, ipa.ErrNotFound)

		plain := mustLogin(t, b, newUserWithPassword(t, b, goodPW), goodPW)
		seen, err := plain.SelfServiceFind(nil)
		if err != nil {
			t.Fatal(err)
		}
		_, showErr := plain.SelfServiceShow("User Self service")
		if serverAtLeast(res.Version, 4, 13) {
			if len(seen) != 0 {
				t.Errorf("plain user sees %d rules on %s", len(seen), res.Version)
			}
			wantIs(t, showErr, ipa.ErrNotFound)
		} else if len(seen) != want || showErr != nil {
			t.Errorf("plain user on %s: %d rules, show %v", res.Version, len(seen), showErr)
		}
	})
}
