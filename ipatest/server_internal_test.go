// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest

import (
	"reflect"
	"testing"

	ipa "github.com/neverlless/goipa"
)

func TestResultHelpers(t *testing.T) {
	rec := map[string]any{"uid": []string{"bob"}}
	if got, want := entry("bob", rec, `Added user "bob"`), map[string]any{"result": rec, "value": "bob", "summary": `Added user "bob"`}; !reflect.DeepEqual(got, want) {
		t.Errorf("entry = %v", got)
	}
	recs := []map[string]any{rec, rec}
	if got, want := list(recs), map[string]any{"result": recs, "count": 2, "truncated": false, "summary": "2 entries returned"}; !reflect.DeepEqual(got, want) {
		t.Errorf("list = %v", got)
	}
	if got, want := *notFound("bob", "user"), (ipa.IpaError{Code: 4001, Name: "NotFound", Message: "bob: user not found"}); got != want {
		t.Errorf("notFound = %+v", got)
	}
	if got, want := *required("uid"), (ipa.IpaError{Code: 3007, Name: "RequirementError", Message: "'uid' is required"}); got != want {
		t.Errorf("required = %+v", got)
	}
}
