// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Copyright 2026 goipa Authors.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client for the FreeIPA JSON-RPC API. It is a maintained
// continuation of github.com/ubccr/goipa.
//
// Create a Client with New and its With* options; on a host enrolled in
// FreeIPA, New() alone reads /etc/ipa. A *Client is safe for concurrent use.
//
// Calls from ubccr/goipa keep their names; calls added since are named
// Object+Verb (GroupAdd, HostGroupShow). Add calls take a struct where FreeIPA
// takes many attributes, positional values where it takes a key and a flag.
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
//	SetSessionID                               an ipa_session cookie. Restoring a web session.
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
// # Any command
//
// RPC calls any command goipa does not wrap and returns the raw response.
// Call decodes the result of any command into a type of your choice; Entry
// reads FreeIPA's attribute encoding (lists, dates, binary values):
//
//	u, _, err := ipa.Call[ipa.Entry](ctx, c, "user_show", []string{"jesse"}, ipa.Options{"all": true})
//	fmt.Println(u.Str("uid"), u.Strs("mail"), u.Time("krbpasswordexpiration"))
//
// FindEntries returns ErrTruncated with the entries it got when the server
// cut a search short; Modify changes single attributes; Batch sends several
// commands in one round trip.
//
// # Typed objects
//
// Host groups, services (with keytab access), HBAC and sudo rules,
// certificates, DNS zones and records, automember rules, and roles,
// privileges and permissions (read only) have typed calls such as
// HostGroupShow and SudoRuleAddOption. Member calls return the updated object
// and a *MemberError for members the server refused; attribute changes go
// through Modify.
//
// # Command catalogue
//
// Commands and LookupCommand describe every FreeIPA command from 4.9.0 on:
// positional arguments, options, and the release that introduced each. The
// data is generated from FreeIPA's API.txt (go generate). New(...,
// WithValidation()) checks each call against it before sending and returns
// ErrInvalidCall (or ErrNotSupported for a feature newer than the server). It
// is off by default, does not check values or required options, and does
// nothing when the server is newer than the newest catalogued release.
//
// # Sessions
//
// On FreeIPA (seen on 4.9.13, 4.12.2 and 4.13.4) the server keeps accepting an ipa_session cookie
// after session_logout: logout only makes the client forget it. Treat a
// session ID as a credential until it expires, and do not log or share it.
// ClearSession drops the ID on the client side only.
//
// # Errors
//
// A FreeIPA error is returned as a bare *IpaError, never wrapped. This applies
// to typed calls, RPC, Call, FindEntries, Modification.Run and each
// BatchResult.Err. Match it with errors.Is against ErrNotFound,
// ErrDuplicateEntry, ErrACI or ErrEmptyModlist (compared by code only), or
// read Code and Data through errors.As or err.(*ipa.IpaError). The Code*
// constants name the other codes.
//
// Member calls (...AddMember, HBACRuleAddUser, ServiceAllow...,
// AutomemberAddCondition, ...) return the updated object together with a
// *MemberError listing what FreeIPA refused. In that case the call itself
// succeeded.
//
// A response with a status other than 200 is a *HTTPError, and a 401 also
// matches ErrUnauthorized. The password form endpoints return
// ErrInvalidPassword, ErrExpiredPassword, ErrPasswordPolicy,
// ErrInvalidCredentials or ErrUnauthorized for the outcomes FreeIPA names.
//
// Some errors come before anything is sent:
//   - ErrNotSupported: the last server seen is too old for the call.
//   - ErrInvalidCall: WithValidation rejected the call.
//
// A Find returns ErrTruncated together with the entries it got, when the
// server cut the search short. This applies to the Finds added in v0.9 and to
// FindEntries. UserFind, GroupFind, HostFind, StageUserFind, SubIDFind,
// FetchOTPTokens, HBACRuleFind and SudoRuleFind did not report it in v1.0 and
// still do not, unless the Client was built WithTruncationErrors.
//
// UserAdd keeps upstream's ErrUserExists for 4002.
//
// Transport, TLS, context and Kerberos errors are returned as they come, or
// wrapped with %w and an "ipa:" prefix. Use errors.Is(err,
// context.DeadlineExceeded). Sentinels are matched with errors.Is, never ==.
// goipa does not log.
//
// # Context
//
// Every Client method that talks to the server has a twin with a Context
// suffix that takes ctx first. The form without a suffix is exactly
// context.Background().
//
// The context bounds the whole call:
//   - the HTTP request,
//   - the one retry after a 401,
//   - a password re-login,
//   - the per-option requests of SudoRuleAddOption.
//
// Cancelling it also stops a call before anything is sent.
//
// APIs added since v0.7 take a context only (Call, FindEntries, Batch,
// Modification.Run). New API in v1 follows that rule: a context-only generic
// or builder, or a method pair.
//
// The Kerberos logins (Login, LoginWithKeytab, LoginFromCCache and their Data
// forms) take no context, because gokrb5 cannot be cancelled. SPNEGO header
// generation inside a Context call is not cancellable either.
//
// goipa stores no context, and the Client's http.Client timeout (1 minute by
// default, or yours via WithHTTPClient) still applies.
package ipa
