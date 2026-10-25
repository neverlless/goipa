// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	"github.com/neverlless/goipa"
)

// TestContract_UnknownOption pins Q44 with a client that does not validate
// (rawAdmin), so the server sees the option instead of the catalogue check.
func TestContract_UnknownOption(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		_, err := b.rawAdmin().RPC("user_show", []string{"admin"}, ipa.Options{"no_such_opt": true})
		var ie *ipa.IpaError
		if !errors.As(err, &ie) || ie.Code != ipa.CodeOption || ie.Name != "OptionError" || ie.Message != "Unknown option: no_such_opt" {
			t.Fatalf("got %#v, want 3005 OptionError \"Unknown option: no_such_opt\"", err)
		}
	})
}
