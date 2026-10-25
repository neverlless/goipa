// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"errors"
	"testing"

	"github.com/neverlless/goipa"
)

// TestContract_CatalogueGate pins V3: a validating client gates a command by
// the catalogue's Since against the version the server reported.
func TestContract_CatalogueGate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		c := b.client()
		c.SetSessionID(b.admin.SessionID())
		if _, err := c.Ping(); err != nil {
			t.Fatal(err)
		}
		cmd, _ := ipa.LookupCommand("passkeyconfig_show", "")
		_, err := c.RPC("passkeyconfig_show", nil, nil)
		if old, _ := ipa.LookupCommand("passkeyconfig_show", c.ServerVersion()); old.Name == "" {
			if !errors.Is(err, ipa.ErrNotSupported) {
				t.Fatalf("server %s, Since %s: got %v, want ErrNotSupported", c.ServerVersion(), cmd.Since, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	})
}
