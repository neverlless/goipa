// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
)

// X3
func TestContractServerVersion(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		if _, err := b.admin.Ping(); err != nil {
			t.Fatal(err)
		}
		v := b.admin.ServerVersion()
		if !strings.HasPrefix(v, "4.") {
			t.Fatalf("version = %q", v)
		}
		if !serverAtLeast(v, 4, 11) {
			if err := b.admin.UserAddPasskey("nobody", testPasskey); !errors.Is(err, ipa.ErrNotSupported) {
				t.Errorf("passkey on %s: err = %v", v, err)
			}
		}
	})
}
