// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import "testing"

func TestParseVersion(t *testing.T) {
	for in, want := range map[string][3]int{
		"4.13.4":           {4, 13, 4},
		"4.9":              {4, 9, 0},
		"4.13.5.dev202610": {4, 13, 5},
	} {
		if got, ok := parseVersion(in); !ok || got != want {
			t.Errorf("parseVersion(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abc", ".4"} {
		if _, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) ok", in)
		}
	}
}
