// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"reflect"
	"strings"
	"testing"
)

// W1
func TestContractWhoAmI(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		got, err := b.admin.WhoAmI()
		if err != nil {
			t.Fatal(err)
		}
		if got.Object != "user" || !strings.HasPrefix(got.Command, "user_show") || !reflect.DeepEqual(got.Arguments, []string{"admin"}) {
			t.Errorf("got %+v", got)
		}
	})
}
