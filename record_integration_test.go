//go:build integration

// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/neverlless/goipa"
)

// TestRecordShapes calls every read-only command that needs no argument, so
// the recorder (IPATEST_RECORD) captures its response for ipatest replay.
func TestRecordShapes(t *testing.T) {
	if os.Getenv("IPATEST_RECORD") == "" {
		t.Skip("IPATEST_RECORD not set")
	}
	for _, b := range realBackends(t) {
		c := b.rawAdmin()
		for _, cmd := range ipa.Commands("") {
			readOnly := strings.HasSuffix(cmd.Name, "_find") || strings.HasSuffix(cmd.Name, "_show")
			if !readOnly || slices.ContainsFunc(cmd.Args, func(p ipa.Param) bool { return p.Required }) {
				continue
			}
			var o ipa.Options
			if slices.ContainsFunc(cmd.Options, func(p ipa.Param) bool { return p.Name == "all" }) {
				o = ipa.Options{"all": true} // as the typed calls send it
			}
			_, _ = c.RPC(cmd.Name, nil, o) // a command the server lacks is simply not recorded
		}
	}
}
