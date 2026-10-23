// Copyright 2026 goipa Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipatest provides a fake FreeIPA server for tests of code that uses
// goipa, so they run without a real IPA.
//
// NewServer starts an in-memory server over TLS and closes it when the test
// ends. Client returns a goipa client wired to it, ClientAs one that already
// holds a session:
//
//	s := ipatest.NewServer(t)
//	c := s.ClientAs("admin")
//
// Calls records every JSON-RPC call the server accepted. Handle overrides one
// method, to inject an error or to serve a command ipatest does not model.
// Separate servers share no state, so parallel tests each get their own.
//
// ipatest started as the fake FreeIPA server in mokey's handler tests (github.com/neverlless/mokey, server/fakeipa_test.go, BSD-3-Clause, same maintainer).
//
// # Auth model
//
// Every authenticated caller may run every command; ACIs are not evaluated;
// OTP codes are not checked. A caller is authenticated by a session from
// Session, ClientAs or a login, or, on /ipa/json, by SetNegotiateUser.
//
// # FreeIPA behaviour kept
//
// Each item is pinned by the test named after it.
//
//   - Q2: /ipa/json, the Kerberos endpoint, answers 401 with
//     "WWW-Authenticate: Negotiate" unless SetNegotiateUser was called; then it
//     serves the call as that user and sets a new session cookie.
//     TestNegotiateUser.
//   - Q12: a request without a Referer starting with https://<host>/ipa is
//     refused: JSON-RPC with error 911 RefererError ("Missing or invalid HTTP
//     Referer, <referer>") in an HTTP 200 envelope, form endpoints with HTTP
//     400. TestRefererJSONRPC.
//   - Q13: /ipa/session/json without a known ipa_session cookie answers HTTP
//     401, as for an expired session. TestSessionsNotShared.
//   - Q14: an unknown command fails with 905 CommandError ("unknown command
//     '<name>'"). TestUnknownCommand.
//   - Q15: session cookies are "ipa_session=MagBearerToken=...; Path=/ipa;
//     Secure; HttpOnly". TestNegotiateUser.
//   - Q18: a command's output is not always {result, value, summary}: hbactest
//     has no result key, and member commands put failed next to result. A
//     HandlerFunc returns the whole output, which is sent verbatim.
//     TestHandleWholeResultObject.
//
// A response's version is the server release, 4.13.4, and its principal is
// <uid>@TEST.LOCAL. An error a HandlerFunc returns without a Name gets the
// FreeIPA name for its code.
//
// # Not modelled
//
// Groups (planned for v0.4); stage users, lockout status and unlock, password
// policy, subordinate IDs, HBAC and sudo rules, hbactest and passkeys
// (planned for v0.5). Until then, Handle is the way to reach them. Kerberos,
// LDAP search filters, size limits, replication and HTTP fault injection are
// left out; wrap HTTPClient's transport for the latter.
package ipatest
