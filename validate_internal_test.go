// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"errors"
	"slices"
	"testing"
)

// No catalogued argument is newer than its command yet, so the test makes one.
func TestValidation_ArgByNameNewer(t *testing.T) {
	cmd := &catalogue[catalogueIndex()["passwd"]]
	j := slices.IndexFunc(cmd.Args, func(p Param) bool { return p.Name == "current_password" })
	if j < 0 {
		t.Fatal("passwd has no current_password argument")
	}
	old := cmd.Args[j].Since
	cmd.Args[j].Since = "4.12.0"
	t.Cleanup(func() { cmd.Args[j].Since = old })

	err := validateCall("passwd", "4.9.13", 2, Options{"current_password": "x"})
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("4.9.13: err = %v, want ErrNotSupported", err)
	}
	if err := validateCall("passwd", "4.12.0", 2, Options{"current_password": "x"}); err != nil {
		t.Errorf("4.12.0: err = %v", err)
	}
}
