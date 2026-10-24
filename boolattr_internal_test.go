// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestBoolAttr(t *testing.T) {
	for _, tc := range []struct {
		json string
		want bool
	}{
		{`{"f":true}`, true},
		{`{"f":[true]}`, true},
		{`{"f":"TRUE"}`, true},
		{`{"f":["TRUE"]}`, true},
		{`{"f":["true"]}`, true},
		{`{"f":false}`, false},
		{`{"f":[false]}`, false},
		{`{"f":["FALSE"]}`, false},
		{`{"f":[]}`, false},
		{`{}`, false},
	} {
		if got := boolAttr(gjson.Parse(tc.json), "f"); got != tc.want {
			t.Errorf("%s: got %v", tc.json, got)
		}
	}
}
