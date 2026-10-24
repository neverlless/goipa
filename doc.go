// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Copyright 2026 goipa Authors.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client for the FreeIPA JSON-RPC API. It is a maintained
// continuation of github.com/ubccr/goipa.
//
// Create a Client with New and its With* options, or NewDefaultClient on a
// host enrolled in FreeIPA. A *Client is safe for concurrent use.
//
// # Which login to use
//
//	RemoteLogin                                password over HTTPS (/ipa/session/login_password).
//	                                           Needs the CA, no Kerberos. Web apps, scripts, hosts not enrolled.
//	Login                                      password through the KDC (Kerberos). Needs krb5.conf
//	                                           (DefaultKerbConf, or WithKrb5Config*) and a realm.
//	LoginWithKeytab, LoginWithKeytabData       keytab; needs krb5.conf (DefaultKerbConf, or WithKrb5Config*)
//	                                           and a realm. Services, daemons.
//	LoginFromCCache, LoginFromCCacheData       an existing ticket cache (kinit); needs krb5.conf
//	                                           (DefaultKerbConf, or WithKrb5Config*). CLI tools.
//	SetSessionID, NewDefaultClientWithSession  an ipa_session cookie. Restoring a web session.
//
// Login is Kerberos, not the web login; use RemoteLogin for a password over
// HTTPS. For a host not enrolled in FreeIPA:
//
//	c, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"), ipa.WithCACert(pem))
//
// When a session expires (HTTP 401) the call is retried once; a fresh session
// another goroutine already obtained is reused. Kerberos clients clear the
// session and retry through SPNEGO. A RemoteLogin client created with
// WithPasswordRelogin logs in again with the password it keeps in memory, one
// login for all goroutines that hit the 401 (a password FreeIPA rejects is
// forgotten; this needs sticky sessions, the default). Any other client gets
// ErrUnauthorized and its session is cleared. The retry relies on FreeIPA's
// httpd answering 401 before it runs the command; a proxy that answers 401
// after forwarding the request breaks that.
//
// A FreeIPA error is returned as a bare *IpaError: match it with errors.Is
// against ErrNotFound and the other sentinels, or with a type assertion.
//
// Every method that talks to the server has a ...Context twin that bounds the
// request with a context, except the Kerberos logins (Login, LoginWithKeytab,
// LoginFromCCache and their Data variants; gokrb5 is not cancellable). RPC
// calls any command goipa does not wrap.
package ipa
