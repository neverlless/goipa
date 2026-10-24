// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"net/url"
	"testing"
)

// V13
func TestContractSyncTokenResults(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		uid := newUserWithPassword(t, b, "Sync-pw-123456")
		form := url.Values{"user": {uid}, "password": {"wrong-Pw-123456"}, "first_code": {"123456"}, "second_code": {"654321"}}
		res := rawPost(t, b, "/ipa/session/sync_token", form, true)
		if res.StatusCode != 200 || res.Header.Get("X-IPA-TokenSync-Result") != "invalid-credentials" {
			t.Errorf("bad password: %d %q", res.StatusCode, res.Header.Get("X-IPA-TokenSync-Result"))
		}
		form.Del("second_code")
		if res := rawPost(t, b, "/ipa/session/sync_token", form, true); res.StatusCode != 400 {
			t.Errorf("missing field: %d", res.StatusCode)
		}
	})
}
