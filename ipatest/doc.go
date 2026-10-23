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
// New starts a server without a testing.TB, for examples and local
// development; call Close when done.
//
// Calls records every JSON-RPC call the server accepted. Handle overrides one
// method, to inject an error or to serve a command ipatest does not model.
// Separate servers share no state, so parallel tests each get their own.
//
// ipatest started as the fake FreeIPA server in mokey's handler tests
// (github.com/neverlless/mokey, server/fakeipa_test.go, BSD-3-Clause, same
// maintainer).
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
//   - Q1: user_find leaves out userclass unless all is true; user_show always
//     has it. TestUserFindFilters, goipa.TestContractFindOmitsUserclass.
//   - Q2: /ipa/json, the Kerberos endpoint, answers 401 with
//     "WWW-Authenticate: Negotiate" unless SetNegotiateUser was called; then it
//     serves the call as that user and sets a new session cookie.
//     TestNegotiateUser.
//   - Q3: user_add and user_mod with random=true return randompassword in
//     that response only, and the password is expired (PasswdExpire, the
//     krbpasswordexpiration attribute, set to now); so is a password that
//     passwd sets for another user. A password users set for themselves
//     (change_password, or passwd on their own account) expires in 90 days.
//     TestUserAddModDel,
//     TestPasswdByAdminExpires, goipa.TestContractRandomPasswordExpired.
//   - Q4: change_password always answers HTTP 200; the outcome is in
//     X-IPA-Pwchange-Result (ok, invalid-password, policy-error), with the
//     policy text in X-IPA-Pwchange-Policy-Error. The "error" result is not
//     emitted; goipa's unknown-status branch is tested with a plain httptest
//     server. TestChangePasswordForm, TestChangePasswordPolicyHeader,
//     goipa.TestContractSetPasswordResults.
//   - Q5: login_password answers 401 with X-IPA-Rejection-Reason
//     invalid-password (unknown user, no password, wrong password),
//     password-expired (PasswdExpire set and not in the future) or
//     user-locked (disabled and preserved accounts too).
//     TestLoginFormRejections, goipa.TestContractLoginRejection.
//   - Q6: after 6 wrong passwords (krbpwdmaxfailure) even the right one is
//     user-locked; a successful login resets the count.
//     TestLoginFormRejections, goipa.TestContractLockout.
//   - Q7: disabling or deleting the last enabled OTP token of a user whose
//     ipauserauthtype is exactly "otp" fails with 4203 DatabaseError "Can't
//     delete last active token while OTP is enabled". TestOTPLastTokenGuard,
//     goipa.TestContractLastOTPToken.
//   - Q8: otptoken_add reads ipatokennotbefore and ipatokennotafter as
//     {"__datetime__": "YYYYmmddHHMMSSZ"} in UTC; any other format fails with
//     3009 ValidationError. TestOTPNotBeforeRecorded, TestOTPBadDatetime,
//     goipa.TestContractOTPLifecycle.
//   - Q9: passwd with a wrong current_password fails with 2100 ACIError
//     "Insufficient access: Invalid credentials". TestPasswdByAdminExpires,
//     goipa.TestContractChangePasswordWrongCurrent.
//   - Q10: user_add of an existing uid fails with 4002 DuplicateEntry.
//     TestUserAddModDel, goipa.TestContractDuplicateUser.
//   - Q11: user_mod that changes nothing fails with 4202 EmptyModlist.
//     TestUserAddModDel, goipa.TestContractUserModNoChange.
//   - Q12: a request without a Referer starting with https://<host>/ipa is
//     refused with HTTP 400 and an HTML page ("denied"), on JSON-RPC and
//     form endpoints alike, after the session check. TestRefererJSONRPC,
//     TestFormsNeedReferer, goipa.TestContractReferer.
//   - Q13: /ipa/session/json closes the connection without a response for
//     an ipa_session cookie "MagBearerToken=<token>" it did not issue (one
//     from another server, or forged): FreeIPA 4.9 to 4.13 crash the httpd
//     child on a token they cannot decrypt, and goipa returns the transport
//     error (io.EOF). Any other unknown or missing cookie answers HTTP 401
//     with "WWW-Authenticate: Negotiate", which goipa maps to
//     ErrUnauthorized. TestSessionsNotShared, TestUnknownSession,
//     goipa.TestContractInvalidSession.
//   - Q14: an unknown command fails with 905 CommandError ("unknown command
//     '<name>'"). TestUnknownCommand, goipa.TestContractUnknownCommand.
//   - Q15: session cookies are "ipa_session=MagBearerToken=...; Path=/ipa;
//     Secure; HttpOnly". TestNegotiateUser,
//     goipa.TestContractSessionCookieFormat.
//   - Q16: LDAP attributes are lists ("uid": ["x"]); nsaccountlock,
//     has_password, has_keytab, preserved and randompassword are scalars;
//     datetimes are [{"__datetime__": "YYYYmmddHHMMSSZ"}] in UTC; empty
//     attributes are left out. TestUserFieldsRoundTrip,
//     goipa.TestContractAttributeShapes.
//   - Q17: user_disable of a disabled user fails with 4010 AlreadyInactive,
//     user_enable of an enabled one with 4009 AlreadyActive.
//     TestUserDisableEnable, goipa.TestContractAlreadyInactive.
//   - Q18: a command's output is not always {result, value, summary}: hbactest
//     has no result key, and member commands put failed next to result. A
//     HandlerFunc returns the whole output, which is sent verbatim.
//     user_del returns {result: {failed: [...]}, value: [deleted...],
//     summary}; user_find returns {result: [...], count, truncated,
//     summary}. TestHandleWholeResultObject, TestUserAddModDel,
//     goipa.TestContractResultShapes.
//   - Q19: user_add with an explicit empty homedirectory fails with 4205
//     ObjectclassViolation, as "" means no value and homeDirectory is
//     required by posixAccount; leaving the option out gets /home/<uid>.
//     TestUserAddEmptyHomeDir, goipa.TestContractUserAddDefaults.
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
