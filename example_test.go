// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// The Kerberos logins need a KDC, so this example is compiled but not run.
func Example_login() {
	c, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"))
	if err != nil {
		log.Fatal(err)
	}
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
	c, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"))
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Login("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
}

// LoginFromCCache reuses a ticket obtained with kinit; compiled but not run.
func ExampleClient_LoginFromCCache() {
	c, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	if err := c.LoginFromCCache("/tmp/krb5cc_1000"); err != nil {
		log.Fatal(err)
	}
}

// RemoteLogin posts the password to /ipa/session/login_password. Its session
// ID can be stored, for example in a web session, and reused later without
// logging in again; compiled but not run.
func ExampleClient_RemoteLogin() {
	c, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	if err := c.RemoteLogin("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
	sid := c.SessionID()

	later, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	later.SetSessionID(sid)
	u, err := later.UserShow("jesse")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Username)
}

// New names the server and CA explicitly, for a host not enrolled in
// FreeIPA; compiled but not run.
func ExampleNew() {
	var caPEM []byte // the contents of the FreeIPA CA certificate

	c, err := ipa.New(
		ipa.WithHost("ipa.example.com"),
		ipa.WithRealm("EXAMPLE.COM"),
		ipa.WithCACert(caPEM),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.RemoteLogin("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
}

// With WithPasswordRelogin the client keeps the password in memory and logs
// in again when the session expires; compiled but not run.
func ExampleWithPasswordRelogin() {
	c, err := ipa.New(
		ipa.WithHost("ipa.example.com"),
		ipa.WithPasswordRelogin(),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.RemoteLogin("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
}

// LoginWithKeytabData takes the keytab from memory, for example a secret
// store; compiled but not run.
func ExampleClient_LoginWithKeytabData() {
	var keytab []byte // read from a secret store
	var krb5conf []byte

	c, err := ipa.New(
		ipa.WithHost("ipa.example.com"),
		ipa.WithRealm("EXAMPLE.COM"),
		ipa.WithKrb5ConfigData(krb5conf),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.LoginWithKeytabData(keytab, "svc-app"); err != nil {
		log.Fatal(err)
	}
}

// Call decodes any command's result; Entry reads FreeIPA's attribute
// encoding. Compiled but not run.
func ExampleCall() {
	c, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	u, _, err := ipa.Call[ipa.Entry](context.Background(), c, "user_show",
		[]string{"jesse"}, ipa.Options{"all": true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Str("uid"), u.Strs("mail"), u.Time("krbpasswordexpiration"))
}

// FindEntries returns the entries it got together with ErrTruncated when the
// server cut the search short; compiled but not run.
func ExampleFindEntries() {
	c, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	hosts, err := ipa.FindEntries(context.Background(), c, "host_find", []string{"web"}, nil, 500)
	if errors.Is(err, ipa.ErrTruncated) {
		fmt.Println("more hosts match; narrow the search")
	} else if err != nil {
		log.Fatal(err)
	}
	for _, h := range hosts {
		fmt.Println(h.Str("fqdn"))
	}
}

// Modify changes single attributes without reading the object first;
// compiled but not run.
func ExampleClient_Modify() {
	c, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	_, err = c.Modify("user_mod", "jesse").
		Set("title", "Engineer").
		Add("mail", "jesse@example.com").
		Run(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

// Batch runs several commands in one round trip; a failed command fills Err
// and does not fail the batch. Compiled but not run.
func ExampleClient_Batch() {
	c, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}
	res, err := c.Batch(context.Background(),
		ipa.BatchCall{Method: "user_show", Args: []string{"jesse"}},
		ipa.BatchCall{Method: "group_show", Args: []string{"admins"}},
	)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range res {
		if r.Err != nil {
			fmt.Println(r.Err)
		}
	}
}

// Commands lists what a server version supports; the sysaccount_* commands
// came with FreeIPA 4.13.0.
func ExampleCommands() {
	old := map[string]bool{}
	for _, c := range ipa.Commands("4.12.0") {
		old[c.Name] = true
	}
	for _, c := range ipa.Commands("4.13.0") {
		if !old[c.Name] {
			fmt.Println(c.Name)
		}
	}
	// Output:
	// sysaccount_add
	// sysaccount_del
	// sysaccount_disable
	// sysaccount_enable
	// sysaccount_find
	// sysaccount_mod
	// sysaccount_policy
	// sysaccount_show
}

// WithValidation checks every call against the command catalogue before it
// is sent; compiled but not run.
func ExampleWithValidation() {
	c, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"), ipa.WithValidation())
	if err != nil {
		log.Fatal(err)
	}
	_, err = c.RPC("user_show", []string{"jesse"}, ipa.Options{"no_such_option": true})
	if errors.Is(err, ipa.ErrInvalidCall) {
		fmt.Println("rejected before sending:", err)
	}
}

// Member calls return the updated group and a *MemberError for members the
// server refused. The example is compiled but not run.
func ExampleClient_HostGroupAddMember() {
	c, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"))
	if err != nil {
		log.Fatal(err)
	}
	g, err := c.HostGroupAddMember("web", []string{"web1.example.com", "typo.example.com"}, nil)

	var me *ipa.MemberError
	if errors.As(err, &me) {
		for _, f := range me.Failures {
			fmt.Println("not added:", f.Name, f.Message)
		}
	} else if err != nil {
		log.Fatal(err)
	}
	fmt.Println(g.Name, g.Hosts)
}

// timingTransport times each request. Any http.RoundTripper fits the same
// way, for example OpenTelemetry's otelhttp.NewTransport.
type timingTransport struct{ next http.RoundTripper }

func (t timingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	res, err := t.next.RoundTrip(r)
	log.Printf("%s %s took %s", r.Method, r.URL.Path, time.Since(start))
	return res, err
}

// WithHTTPClient wraps the transport; compiled but not run. The caller owns
// the TLS settings of the client it passes: replace http.DefaultTransport
// with a transport that trusts the FreeIPA CA.
func ExampleWithHTTPClient() {
	hc := &http.Client{
		Timeout:   30 * time.Second,
		Transport: timingTransport{next: http.DefaultTransport},
	}
	c, err := ipa.New(
		ipa.WithHost("ipa.example.com"),
		ipa.WithRealm("EXAMPLE.COM"),
		ipa.WithHTTPClient(hc),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.RemoteLogin("jesse", "secret"); err != nil {
		log.Fatal(err)
	}
}

func ExampleClient_HostAdd() {
	s := ipatest.New()
	defer s.Close()
	c := s.ClientAs("admin")

	h, err := c.HostAdd(&ipa.Host{FQDN: "web1.example.com"}, true, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(h.FQDN, h.RandomPassword != "")

	if err := c.HostDelete(false, h.FQDN); err != nil {
		log.Fatal(err)
	}
	// Output: web1.example.com true
}
