// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"fmt"
	"log"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// The Kerberos logins need a KDC, so this example is compiled but not run.
func Example_login() {
	c := ipa.NewClient("ipa.example.com", "EXAMPLE.COM")
	if err := c.LoginWithKeytab("/etc/app/app.keytab", "svc-app"); err != nil {
		log.Fatal(err)
	}

	u, err := c.UserShow("jesse")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Username, u.Email)
}

// stubTB lets an example run ipatest, which wants a testing.TB.
type stubTB struct {
	testing.TB
	cleanups []func()
}

func (*stubTB) Helper()             {}
func (b *stubTB) Cleanup(fn func()) { b.cleanups = append(b.cleanups, fn) }

func ExampleClient_RPC() {
	tb := &stubTB{}
	s := ipatest.NewServer(tb)
	defer s.Close()

	res, err := s.ClientAs("admin").RPC("ping", nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Principal, res.Version)
	// Output: admin@TEST.LOCAL 4.13.4
}
