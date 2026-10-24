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
// Every authenticated caller may run every command; ACIs are not evaluated
// except the group member checks of Q24 and the pwpolicy_show check of Q32,
// so where FreeIPA answers 2100
// ACIError ipatest runs the command: an ordinary user deleting a missing OTP
// token gets 4001 NotFound here and "2100 Insufficient access" from FreeIPA.
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
//     user-locked (disabled and preserved accounts too). FreeIPA before
//     4.13.1 answers invalid-password instead of user-locked (issue 9891).
//     TestLoginFormRejections, goipa.TestContractLoginRejection.
//   - Q6: after 6 wrong passwords (krbpwdmaxfailure) even the right one is
//     user-locked; a successful login resets the count. FreeIPA before
//     4.13.1 reports invalid-password here too (issue 9891); ipatest
//     models 4.13.4.
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
//     error (io.EOF). A session ended with ExpireSession, and any other
//     unknown or missing cookie, answers HTTP 401 with "WWW-Authenticate:
//     Negotiate", which goipa maps to ErrUnauthorized. TestSessionsNotShared,
//     TestUnknownSession, TestExpireSession,
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
//   - Q19: user_add, user_mod and stageuser_mod with an explicit empty
//     homedirectory fail with 4205 ObjectclassViolation, as "" means no value
//     and homeDirectory is required by posixAccount; leaving the option out
//     gets /home/<uid> on add and keeps the value on mod.
//     TestUserAddEmptyHomeDir, TestUserModEmptyHomeDir, goipa.TestContractUserAddDefaults.
//   - Q20: group_show returns members unless no_members is true (all
//     overrides it); group_find returns them only with no_members false or
//     all true. Empty member lists are left out; gidnumber only on POSIX
//     groups; objectclass, ipauniqueid and dn only with all.
//     TestGroupFind_HidesMembersByDefault, TestGroupShow_Shape,
//     TestGroupObjectClasses.
//   - Q21: group_add of an existing cn fails with 4002 ("group with name
//     "<cn>" already exists"); a POSIX group without gidnumber gets the next
//     one from 1000000; nonposix and external groups get none; group_mod that
//     changes nothing fails with 4202; a missing group is 4001
//     "<cn>: group not found". TestGroupAddModDel, TestGroupShow_NotFound.
//   - Q22: group_del returns {result: {failed: []}, value: [cns], summary}
//     and drops the group from other groups, from users, from the groups of
//     HBAC and sudo rules, and its password policy. user_del drops the user
//     from every group's members and managers and from the users of HBAC and
//     sudo rules, preserved or not.
//     TestGroupDel_Shape, TestUserDel_LeavesGroups, TestUserDel_LeavesRules,
//     TestGroupDel_LeavesRulesAndPolicy.
//   - Q23: group_{add,remove}_member and the _member_manager commands report
//     per-member problems ("This entry is already a member", "This entry is
//     not a member", "no such entry") in failed, next to result, as
//     {member|membermanager: {user: [[name, msg]], group: [...]}} (member
//     also carries empty service and idoverrideuser) with error null.
//     A group added to itself fails with "A group may not be added as a member
//     of itself".
//     TestGroupAddMember_FailedIsSiblingOfResult, TestGroupAddMember_Self,
//     TestGroupAddMember_AlreadyMember, TestGroupAddMemberManager_FailedKey.
//   - Q24: member commands are allowed for uid admin, members of admins,
//     ManagerUsers and members of a ManagerGroups group; manager commands for
//     admins only. A caller who is not allowed gets no error: every requested
//     member lands in failed with "Insufficient access: Insufficient 'write'
//     privilege to the 'member' attribute of entry '<dn>'.".
//     TestGroupAddMember_DeniedGoesToFailed, TestGroupAddMember_ManagerAllowed.
//   - Q25: nesting is transitive: memberindirect_user and
//     memberindirect_group list what comes through member groups,
//     memberof_group the direct parents. user_show has memberof_group (direct) and
//     memberofindirect_group; user_find with all folds the nested groups into
//     memberof_group and has no memberofindirect_group. Membership is the
//     union of User.Groups and Group.Members.
//     TestUserShow_IndirectGroups, TestUserFind_NestedGroupsFlattened.
//   - Q26: street, l, st, postalcode and preferredlanguage come back only
//     with all true; title, ou and ipapasskey always. mail lists
//     User.Emails, else User.Email; user_add and user_mod take mail as a
//     string or a list and replace the whole set.
//     TestIpatest_AddressNeedsAll, goipa.TestUserMod_KeepsExtras.
//   - Q27: host_show returns members (memberof_hostgroup, managedby_host)
//     unless no_members is true (all overrides it); host_find returns them
//     only with no_members false or all true. krbprincipalname is
//     host/<fqdn>@TEST.LOCAL; has_keytab and has_password are scalar bools;
//     a missing host is 4001 "<fqdn>: host not found". Every new server
//     already holds its own host, ipa.test.local, with a keytab.
//     TestHostFind_HidesMembersByDefault, TestHostShow_Shape,
//     TestHostShow_NotFound.
//   - Q28: stage users live in their own store, with dn
//     uid=<uid>,cn=staged users,cn=accounts,cn=provisioning,dc=test,dc=local,
//     nsaccountlock always true, no memberof_*, and uidnumber and gidnumber
//     ["-1"] (the DNA magic value stageuser_add.pre_callback sets) until
//     activation.
//     stageuser_find leaves out userclass unless all is true, as Q1.
//     TestContractStageFindUserclassNeedsAll, TestContractStageUserLifecycle.
//   - Q29: stageuser_add without givenname or sn is 3007; a duplicate stage
//     uid is 4002 `stage user with name "<uid>" already exists`; active
//     users are not checked. stageuser_del has the user_del shape; a missing
//     entry is 4001 "<uid>: stage user not found"; it ignores preserve.
//     TestStageUserAdd_Required, TestStageUserDuplicateAndDelete.
//   - Q30: stageuser_activate moves the record to the active users with a
//     fresh uidnumber and answers with the active entry (all attributes),
//     summary "Stage user <uid> activated". If the active uid exists it is
//     4002 `active user with name "<uid>" already exists` and the stage entry
//     stays. TestContractStageActivateSummary, TestStageUserDuplicateAndDelete.
//   - Q31: user_status answers one entry for ipa.test.local: server and now
//     are scalars, krblastfailedauth is ["N/A"] or
//     [{"__datetime__": "YYYYmmddHHMMSSZ"}] for the last wrong password
//     (User.LastFailedLogin), krbloginfailedcount is the scalar "0"
//     until a login fails and ["n"] afterwards, as on a real IPA. The summary
//     is "Account disabled: True|False"; a missing user is 4001. user_unlock
//     zeroes the counter. TestContractUserStatusAndUnlock, TestUserStatus_*.
//   - Q32: New seeds global_policy with FreeIPA's defaults (90 days, 1 hour,
//     minlength 8, 6 failures, 60 s interval, 600 s lockout, grace limit -1).
//     pwpolicy_show without cn is the global policy; option user resolves the
//     lowest cospriority among the user's groups, nested ones included, else
//     global (4001 for a missing user, "<cn>: password policy not found" for
//     an unknown cn). Numbers are one-element string lists in wire units. In
//     global_policy the krb* attributes, the credits and the two checks
//     (["TRUE"]/["FALSE"]) are always present; a group policy has
//     cospriority, passwordgracelimit (-1 unless set) and only the attributes
//     that were set; zero optional ones are omitted.
//     A caller who is neither uid admin nor a member of admins gets 4001
//     `<cn or None>: password policy not found` (the ACI hides the entry;
//     also for option user), not 2100. With option user the answer has no
//     cospriority, as pwpolicy_show asks add_cospriority for a cn of None.
//     pwpolicy_add needs an existing
//     group (4001) and cospriority (3007); login_password and change_password
//     use the global MaxFailures (0 disables lockout) and MinLength.
//     pwpolicy_show takes only all, raw, rights, user and version; any other
//     option is 3005 OptionError "Unknown option: <name>".
//     TestContractPwPolicyGlobal, TestUserPwPolicy_Resolution,
//     TestPwPolicy_AddDelAndLoginUseGlobal, TestPwPolicyShow_UnknownOption,
//     TestPwPolicyShow_GroupOmitsUnset, TestUserPwPolicy_OmitsCospriority,
//     TestPwPolicyShow_HiddenFromPlainUser, TestContractPwPolicyPlainUser.
//   - Q33: sub-ID ranges start at 2147483648 and advance by 65536 (uid and gid
//     equal). subid_find filters by ipaowner, ipauniqueid, ipasubuidnumber and
//     description; values are lists of strings, plus dn
//     ipauniqueid=<id>,cn=subids,cn=accounts,dc=test,dc=local and objectclass.
//     subid_generate takes the owner from ipaowner, else the caller; an unknown
//     owner is 4001 "<owner>: user not found"; a second range is 4002
//     `Subordinate id with with name "<id>" or for user "<owner>" already
//     exists.` (FreeIPA's typo). A non-preserving user_del drops the range.
//     TestContractSubIDGenerate, TestSubID_FindAndUserDelete.
//   - Q34: New seeds the HBAC rule allow_all (description "Allow all users to
//     access any host from any host", user, host and service category all),
//     as every FreeIPA has. hbacrule_find and sudorule_find hide members
//     unless all is true or no_members is false (as Q1/U1); ipaenabledflag
//     is ["TRUE"]/["FALSE"], categories are one-element lists, sudoorder a
//     one-element string list. dn is ipaUniqueID=<uuid>,cn=hbac,... and
//     ipaUniqueID=<uuid>,cn=sudorules,cn=sudo,...
//     TestHBACRuleFind_AllFields, TestSudoRuleFind_AllFields,
//     TestRuleFindMembersVisibility, TestRuleFindFilters,
//     TestRuleAddUserFailures.
//   - Q35: hbactest needs user, targethost and service (3007 otherwise) and
//     answers with no result key: value, summary "Access granted: True|False",
//     and matched, notmatched, error and warning as lists or null. The rules
//     are the enabled ones, or those named in rules, which are evaluated even
//     when disabled. If a name in rules is unknown nothing is evaluated: value
//     false, summary "Unresolved rules in --rules", error the unknown names,
//     matched and notmatched null. A rule matches when its user, host and
//     service parts all do: category all, the name listed, or a group of the
//     user (nested ones included) or a direct hostgroup of the host listed;
//     host groups are not expanded through nesting, service groups not at
//     all. An unknown user or host just has no groups.
//     TestContractHBACTest, TestHBACTest_*.
//   - Q36: user_add_passkey and user_remove_passkey take one mapping,
//     passkey:<id>,<key>[,<userid>]; id and key must be standard base64 and
//     the key a PKIX public key, else 3009 `invalid 'passkey': …`. A duplicate
//     is 4038 `'ipapasskey' already contains '<mapping>'`, an absent one on
//     remove 4026 `'ipapasskey' does not contain '<mapping>'`. The answer
//     holds uid and ipapasskey. Any caller may manage any user's mappings.
//     TestPasskeyCommands, TestContractPasskeys.
//   - Q37: /ipa/session/sync_token answers HTTP 400 with an HTML body when
//     user, password, first_code or second_code is missing. Otherwise it is
//     200 with X-IPA-TokenSync-Result invalid-credentials (unknown user, no
//     password or a different one, no enabled token of the user, or none with
//     the given token UUID, or a code that is not Digits digits) or ok. Codes
//     are not checked against a secret. The Referer check of the form
//     endpoints applies; SyncOTPToken sends one. TestContractSyncTokenResults,
//     TestSyncOTPToken.
//
// A response's version is the server release, 4.13.4, and its principal is
// <uid>@TEST.LOCAL. An error a HandlerFunc returns without a Name gets the
// FreeIPA name for its code.
//
// # Not modelled
//
// Of HBAC and sudo rule management, only find, add, del and the member and
// option calls the tests need; Handle is the way to reach the rest, as for
// config_*, subid_show, stageuser_add_passkey and stageuser_remove_passkey.
// Stage user passwords are not modelled: userpassword is ignored and random
// behaves as for active users. Kerberos, LDAP search filters, size limits,
// replication and HTTP fault injection are left out; wrap HTTPClient's
// transport for the latter.
package ipatest
