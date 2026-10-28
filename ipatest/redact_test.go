// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import "testing"

func TestRedact_NestedAndNonMutating(t *testing.T) {
	in := map[string]any{"a": []any{map[string]any{"UserPassword": "s", "k": "v"}}}
	out := redact(in).(map[string]any)["a"].([]any)[0].(map[string]any)
	if out["UserPassword"] != "REDACTED" || out["k"] != "v" {
		t.Errorf("out = %v", out)
	}
	if in["a"].([]any)[0].(map[string]any)["UserPassword"] != "s" {
		t.Error("input mutated")
	}
}
