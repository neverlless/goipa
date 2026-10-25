// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/neverlless/goipa"
)

func wantCode(t *testing.T, what string, err error, code int) {
	t.Helper()
	var ie *ipa.IpaError
	if !errors.As(err, &ie) || ie.Code != code {
		t.Errorf("%s: err = %v, want code %d", what, err, code)
	}
}

// V12
func TestContractPasskeys(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		res, err := b.admin.RPC("ping", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !serverAtLeast(res.Version, 4, 11) {
			t.Skipf("passkeys need FreeIPA 4.11, server is %s", res.Version)
		}
		uid := newUID(t, b)
		if _, err := b.admin.UserAdd(&ipa.User{Username: uid, First: "Go", Last: "Test"}, false); err != nil {
			t.Fatal(err)
		}
		if err := b.admin.UserAddPasskey(uid, testPasskey); err != nil {
			t.Fatal(err)
		}
		if u, err := b.admin.UserShow(uid); err != nil || !slices.Equal(u.Passkeys, []string{testPasskey}) {
			t.Fatalf("show = %+v, %v", u, err)
		}
		wantCode(t, "duplicate add", b.admin.UserAddPasskey(uid, testPasskey), ipa.CodeAlreadyContainsValue)
		if err := b.admin.UserRemovePasskey(uid, testPasskey); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "absent remove", b.admin.UserRemovePasskey(uid, testPasskey), ipa.CodeAttrValueNotFound)
		wantCode(t, "invalid mapping", b.admin.UserAddPasskey(uid, "passkey:notbase64,x"), ipa.CodeValidation)
	})
}
