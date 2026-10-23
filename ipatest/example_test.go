// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipatest_test

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

func ExampleNewServer() {
	var t *testing.T // the *testing.T of the test using the server

	s := ipatest.NewServer(t)
	c := s.ClientAs("admin")
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
}

func ExampleServer_Handle() {
	var t *testing.T // the *testing.T of the test using the server

	s := ipatest.NewServer(t)
	s.Handle("user_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4001, Message: "jesse: user not found"}
	})
	if _, err := s.ClientAs("admin").UserShow("jesse"); !errors.Is(err, ipa.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
