// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"fmt"
	"log"

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

func ExampleClient_RPC() {
	s := ipatest.New()
	defer s.Close()

	res, err := s.ClientAs("admin").RPC("ping", nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Principal, res.Version)
	// Output: admin@TEST.LOCAL 4.13.4
}

// Login gets a Kerberos ticket for the password, which later calls
// authenticate with; it needs /etc/krb5.conf and a KDC, so it is compiled but
// not run.
func ExampleClient_Login() {
	c := ipa.NewClient("ipa.example.com", "EXAMPLE.COM")
	if err := c.Login("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
}

// LoginFromCCache reuses a ticket obtained with kinit; compiled but not run.
func ExampleClient_LoginFromCCache() {
	c := ipa.NewDefaultClient()
	if err := c.LoginFromCCache("/tmp/krb5cc_1000"); err != nil {
		log.Fatal(err)
	}
}

// RemoteLogin posts the password to /ipa/session/login_password. Its session
// ID can be stored, for example in a web session, and reused later without
// logging in again; compiled but not run.
func ExampleClient_RemoteLogin() {
	c := ipa.NewDefaultClient()
	if err := c.RemoteLogin("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
	sid := c.SessionID()

	later := ipa.NewDefaultClientWithSession(sid)
	u, err := later.UserShow("jesse")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Username)
}
