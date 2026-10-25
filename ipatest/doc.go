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
// # Seed helpers
//
// The helpers follow one convention:
//
//   - AddX(key, X) creates or replaces an object.
//   - X(key) returns a copy of it, taken under the server's lock.
//   - SetX is used where the object always exists (SetPwPolicy) or for
//     server settings (SetVersion, SetReplay, SetNegotiateUser).
//   - AddOTPToken and AddSubID take no key and return the stored value,
//     because the server generates their IDs.
//   - DNS zones, automember rules and certificates have no seed helper;
//     create them with client calls.
//
// The ipatest types hold the seed input form with FreeIPA's default as the
// zero value, so some fields differ from the matching ipa types: Disabled
// instead of Enabled, Group.Members instead of Users, User.Telephone and
// User.SSHPubKeys. The RBAC helpers take the ipa types and ignore their
// Name.
//
// # Compatibility
//
// The exported API of ipatest follows goipa's semver. That covers types,
// fields, methods and the HandlerFunc and NewRecorder signatures.
//
// Behaviour does not follow semver. ipatest follows real FreeIPA, and a
// minor release may change a response, an error code, a default or a
// replayed recording to match what FreeIPA does, or model a command that
// used to be answered by replay or 905. Every such change is listed in
// CHANGELOG under "ipatest".
//
// Quirk numbers (Q1, Q2, ...) are never reused. The default SetVersion may
// move to the newest supported FreeIPA in a minor release; pin it in tests
// that depend on it. Handle overrides always win and are not validated.
//
// # Auth model
//
// Every authenticated caller may run every command; ACIs are not evaluated
// except the group member checks of Q24, the pwpolicy_show check of Q32, the
// cert_show check of Q95 and the RBAC reads of Q122, so where FreeIPA
// answers 2100 ACIError ipatest runs the command: an ordinary user deleting a
// missing OTP token gets 4001 NotFound here and "2100 Insufficient access"
// from FreeIPA.
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
//     Negotiate" and FreeIPA's unauthorized.html page as "text/html;
//     charset=UTF-8", which goipa maps to ErrUnauthorized. A real session
//     expires the same way, as mod_auth_gssapi then sees no session.
//     TestSessionsNotShared, TestUnknownSession, TestExpireSession,
//     goipa.TestContractInvalidSession, goipa.TestContractNoSession.
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
//     TestUserAddEmptyHomeDir, TestUserModEmptyHomeDir,
//     goipa.TestContractUserAddDefaults.
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
//   - Q25: nesting is transitive: memberindirect_user and memberindirect_group
//     list what comes through member groups, memberof_group the direct parents.
//     user_show has memberof_group (direct) and memberofindirect_group;
//     user_find with all folds the nested groups into memberof_group and has no
//     memberofindirect_group. Membership is the union of User.Groups and
//     Group.Members. TestUserShow_IndirectGroups,
//     TestUserFind_NestedGroupsFlattened.
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
//     entry is 4001 "<uid>: stage user not found".
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
//     user, a host group of the host (nested ones included) or a service
//     group holding the service (Q150) listed. An unknown user or host just
//     has no groups.
//     TestContractHBACTest, TestHBACTest_*,
//     goipa.TestContractHBACTestNestedHostGroup.
//   - Q36: user_add_passkey and user_remove_passkey take one mapping,
//     passkey:<id>,<key>[,<userid>]; id and key must be standard base64 and
//     the key a PKIX public key, else 3009 `invalid 'passkey': …`. A duplicate
//     is 4038 `'ipapasskey' already contains '<mapping>'`, an absent one on
//     remove 4026 `'ipapasskey' does not contain '<mapping>'`. The answer
//     holds uid and ipapasskey, left out when empty, or the whole user with
//     all. Any caller may manage any user's mappings. Before 4.11
//     (SetVersion) both commands are 905, as Q44.
//     TestPasskeyCommands, TestContractPasskeys, TestContractPasskeyAnswer,
//     TestService_AuthIndVersion.
//   - Q37: /ipa/session/sync_token answers HTTP 400 with an HTML body when
//     user, password, first_code or second_code is missing. Otherwise it is
//     200 with X-IPA-TokenSync-Result invalid-credentials (unknown user, no
//     password or a different one, no enabled token of the user, or none with
//     the given token UUID, or a code that is not Digits digits) or ok. Codes
//     are not checked against a secret. The Referer check of the form
//     endpoints applies; SyncOTPToken sends one. TestContractSyncTokenResults,
//     TestSyncOTPToken.
//   - Q38: whoami answers {"object": "user", "command": "user_show/1",
//     "arguments": [<caller uid>]} with no "result" key. TestWhoAmI,
//     TestContractWhoAmI.
//   - Q39: session_logout answers {"result": null} with a cookie that
//     deletes ipa_session (Max-Age=0); goipa clears its session on it, so
//     its next call has none and gets HTTP 401. The server keeps the session
//     (Q155). The exact cookie FreeIPA sends was not captured but is a
//     deletion (the real-server legs of TestContractSessionLogoutGives401
//     and TestContractStaleSessionCookie).
//     TestContractSessionLogoutGives401, TestSessionLogout.
//   - Q40: user_find, group_find and host_find honour sizelimit > 0: the
//     first n entries in sorted order (a numeric string such as "5" counts
//     too), truncated true and a
//     SearchResultTruncated warning (code 13017). TestFindEntries_Truncated,
//     TestContractFindTruncated.
//   - Q41: user_mod (and stageuser_mod) takes setattr, addattr and delattr
//     for the attributes it models, mail included, applied in that order.
//     setattr attr=v replaces and attr= clears; addattr of a value already
//     present adds nothing, so alone it is 4202 EmptyModlist;
//     delattr of an absent value is 4026 AttrValueNotFound "'attr' does not
//     contain 'v'"; delattr of an attribute that has no values (and is not
//     set or added in the same call) is first 3009 "invalid 'attr': No such
//     attribute on this entry", as process_attr_options; an attribute the
//     fake does not model is 4205 ObjectclassViolation `attribute "attr" not
//     allowed`. The duplicate addattr and the unknown attribute were
//     verified on FreeIPA 4.9.13 and 4.13.4; all five are checked by
//     TestContractModify; TestModify_Apply pins
//     the fake. More than one value for a single-valued attribute (two
//     setattr values, or addattr on a set one) is 4207 OnlyOneValueAllowed
//     "attr: Only one value allowed.", TestModify_SingleValued. Only mail,
//     ipasshpubkey and ipauserauthtype take several values here;
//     telephonenumber, mobile and userclass are multivalue in FreeIPA but
//     one string in the fake, so the fake rejects what FreeIPA accepts.
//   - Q42: batch runs each {"method", "params": [args, options]} entry as
//     the caller, through the same lookup as a top-level call (Handle, then
//     the modelled commands, else 905), with the batch's version when the
//     entry has none, and answers {"count": n, "results": [...]}: each
//     command's output plus "error": null, or {error, error_code,
//     error_name, error_kw} for a failure, without stopping the rest. An
//     entry without method or params is 3007 RequirementError; params that
//     are not [list, dict] are 3008 ConversionError "invalid 'params': must
//     contain a tuple (list, dict)", as batch.py's _validate_request.
//     Calls records the batch call, then each nested call. A nested batch
//     is dispatched recursively, and a nested session_logout sends no
//     deletion cookie (neither verified against FreeIPA). TestBatch,
//     TestBatch_MiddleFails, TestBatchMalformedEntries,
//     goipa.TestContractBatch.
//   - Q43: passkeyconfig_show answers FreeIPA's default configuration,
//     iparequireuserverification [true], with null value and summary; only
//     its success is pinned against FreeIPA, the attribute shape follows
//     passkeyconfig.py. goipa.TestContract_CatalogueGate.
//   - Q44: a modelled command given an option it does not take at the
//     reported release (arguments by name count, as in ipalib's
//     __options_2_params) fails with 3005 OptionError "Unknown option:
//     <name>", the first unknown name in sorted order; FreeIPA picks an
//     arbitrary one. Inside a batch it is that entry's error.
//     TestServer_UnknownOption, TestServer_BatchUnknownOption,
//     goipa.TestContract_UnknownOption.
//   - Q45: a modelled command added after the release SetVersion reports
//     (subid_* before 4.9.7, passkey commands before 4.11.0) is 905 "unknown
//     command '<name>'", as Q14. Q44 and Q45 follow the ipa command
//     catalogue and skip Handle overrides. TestServer_CommandNewerThanVersion,
//     TestServer_HandleBypassesCatalogue.
//   - Q50: hostgroup_show, _find, _add, _del and the member and member
//     manager calls. A host's membership is the union of Host.HostGroups and
//     HostGroup.Hosts, as R2 for users; host_show's memberof_hostgroup lists
//     it and removing the host clears both. hbactest sees the union too. A
//     missing host group is 4001 "<cn>: host group not found"; hostgroup_del
//     drops the group from other host groups, hosts, HBAC and sudo rules and
//     service keytab access, and host_del (case-insensitive) drops the host
//     from host groups, HBAC and sudo rules and service managedby and
//     keytab access and deletes its services (Q146). Member problems (no
//     such entry, already a member, not a member, the group itself,
//     Insufficient access for callers that are neither admins nor member
//     managers) come back in failed under
//     member.{host,hostgroup} or membermanager.{user,group}, as U3.
//     TestContractHostGroupLifecycle, TestContractHostGroupMemberMissing,
//     TestContractHostGroupManagers, TestHostGroupMembers_Fake,
//     TestHostGroupDelete_DropsReferences,
//     goipa.TestHostDelete_DropsReferences,
//     goipa.TestHostGroupDelete_DropsRuleAndKeytabReferences.
//   - Q51: a host in a nested host group is in the parent's
//     memberindirect_host, not member_host, and host_show lists the parent
//     in memberofindirect_hostgroup; a nested group's own nested groups are
//     memberindirect_hostgroup. hostgroup_* lower-case the host group
//     name (AddHostGroup and HostGroup too); hostgroup_find's criteria
//     match case-insensitively. Host group names in rules, keytab access,
//     nested groups, automember rules and the seed helpers resolve in any
//     case and are kept lower-cased.
//     TestContractHostGroupMembers, TestHostGroupShow,
//     goipa.TestContractHostGroupMixedCase,
//     goipa.TestContractHostGroupMixedCaseReferences,
//     goipa.TestContractAutomemberHostGroupMixedCase.
//   - Q140: host group cycles are accepted, as on FreeIPA: a group reachable
//     from itself is in its own memberindirect_hostgroup, while
//     memberofindirect_hostgroup (the parents' ancestors) leaves it out.
//     goipa.TestContractHostGroupCycle.
//   - Q141: hostgroup_* member failures spell the name as given, mixed case
//     included; removing a host or host group that is not a member, known or
//     not, is "This entry is not a member". The denial text names the
//     'member' attribute for members and 'memberManager' for member
//     managers; member managers may not change the managers.
//     goipa.TestContractHostGroupMemberSpelling,
//     goipa.TestContractHostGroupDenied.
//   - Q146: host_del also deletes the services of the host (<svc>/<fqdn>).
//     goipa.TestContractHostDeleteServices,
//     goipa.TestHostDelete_DropsReferences.
//   - Q147: hostgroup_del and group_del leave the automember rule of the
//     group in place; FreeIPA keeps it with a dangling automembertargetgroup.
//     goipa.TestContractHostGroupDeleteKeepsAutomember.
//   - Q90: cert_request signs the CSR with an in-memory CA (ECDSA P-256,
//     "CN=Certificate Authority,O=TEST.LOCAL", created on first use) for an
//     existing host principal host/<fqdn>[@REALM] only; the subject is "CN=<the
//     CSR's CN>,O=TEST.LOCAL", validity two years, serials sequential from 2.
//     cert_request and cert_show answer certificate as base64 DER,
//     serial_number as a JSON number, valid_not_before/valid_not_after in
//     ipalib's "Mon Jan 02 15:04:05 2006 UTC" layout, and revoked.
//     goipa.TestContractCert.
//   - Q91: cert_revoke marks the certificate revoked; cert_show then answers
//     revoked true and revocation_reason, the code given (default 0).
//     goipa.TestContractCert.
//   - Q92: cert_show and cert_revoke of an unknown serial are 4001 NotFound
//     "Certificate ID 0x<hex> not found"; before 4.12 (verified on 4.9.13,
//     4.10 and 4.11 not checked) Dogtag's 404 surfaces as 4301
//     CertificateOperationError. goipa.TestContractCertShowMissing.
//   - Q93: a CSR whose CN is not the principal's host is 3009
//     ValidationError on csr. goipa.TestContractCertRequestWrongCN.
//   - Q94: the default profile, caIPAserviceCert, takes RSA keys only; any
//     other key is 4301 CertificateOperationError "Certificate operation
//     cannot be completed: Key Type RSA Not Matched".
//     goipa.TestContractCertRequestECDSA.
//   - Q95: cert_show by a caller who is neither uid admin nor in admins is
//     2100 ACIError: FreeIPA needs Retrieve Certificates from the CA or a
//     host principal named in the subject, and no plain user is either.
//     goipa.TestContractCertShowPlainUser.
//   - Q144: the principal of cert_request is case-sensitive: host/<FQDN>
//     in another case, like any unknown principal, is 4001 "The principal
//     for this request doesn't exist."; the CSR's CN matches the host in any
//     case and the subject and SAN keep its spelling.
//     goipa.TestContractCertPrincipalCase.
//   - Q145: cert_revoke of a revoked certificate fails and keeps the first
//     reason: before 4.12 4301 "Certificate operation cannot be completed:
//     ERROR (Attempt to revoke non-existent certificate(s).)", on 4.12 4035
//     HTTPRequestError "Request failed with status 400: Non-2xx response
//     from CA REST API: 400. certificate #<hex> has already been revoked",
//     from 4.13 4301 "Certificate operation cannot be completed: Unable to
//     communicate with CMS (certificate 0x<hex> has already been revoked)"
//     (seen on 4.9.13, 4.12.2 and 4.13.4; 4.10 and 4.11 are not checked).
//     goipa.TestContractCertRevokeTwice.
//   - Q70: hbacrule_add stores description and the user, host and service
//     categories; hbacrule_show of a missing rule is 4001 "<cn>: HBAC rule
//     not found" and shows members unless no_members is true.
//     goipa.TestContractHBACRuleLifecycle, goipa.TestHBACRuleShow_FakeRule.
//   - Q71: hbacrule_enable and hbacrule_disable answer result true even
//     when the rule is already in that state, unlike user_enable (Q17);
//     verified on FreeIPA 4.9.13, 4.12.2 and 4.13.4.
//     goipa.TestContractHBACRuleEnableDisable.
//   - Q72: hbacrule_{add,remove}_{user,host,service} take user/group,
//     host/hostgroup and hbacsvc/hbacsvcgroup and answer as group_add_member
//     with failed.memberuser, failed.memberhost and failed.memberservice:
//     adding a missing name is "no such entry", adding a member "This entry
//     is already a member"; removing any name that is not a member, missing
//     or not, is "This entry is not a member" (unlike group_remove_member).
//     goipa.TestContractHBACRuleMemberMissing,
//     goipa.TestContractHBACRuleMembers.
//   - Q73: adding users, hosts or services to a rule whose matching category
//     is all is 4303 MutuallyExclusiveError "users cannot be added when user
//     category='all'" (hosts/host, services/service); removing is not
//     checked. goipa.TestContractHBACRuleCategoryConflict.
//   - Q74: the HBAC services and service groups are FreeIPA's defaults
//     (sshd, login, sudo, ... and Sudo, ftp) and cannot be changed; a host
//     group exists when the host group store has it (AddHostGroup,
//     hostgroup_add). goipa.TestContractHBACRuleMembers,
//     goipa.TestContractHBACRuleWithTest.
//   - Q100: dnszone_add makes the name absolute and answers FreeIPA's
//     defaults: active, dynamic update off, idnssoamname the server
//     (ipa.test.local.), idnssoarname the relative "hostmaster", SOA refresh
//     3600, retry 900, expire 1209600, minimum 3600, a serial from the clock,
//     an apex "@" with the server as NS and a "_kerberos" TXT record with the
//     realm. DNS names (idnsname, idnssoamname, idnssoarname) come back as
//     {"__dns_name__": name}. A second add is 4002 DuplicateEntry. New
//     servers hold the zone test.local. with "ipa" A 127.0.0.1.
//     goipa.TestContractDNSZoneLifecycle, goipa.TestContractDNSRecords.
//   - Q101: dnszone_disable and dnszone_enable of a zone already in that
//     state succeed. goipa.TestContractDNSZoneLifecycle.
//   - Q102: dnsrecord_add merges the values into the name, creating it;
//     values all present already are 4202 EmptyModlist, no *record option is
//     3005 OptionError. A name in the zone given absolute is made relative,
//     the zone itself is "@", and the "@" entry of dnsrecord_show/find is the
//     zone entry with its SOA attributes. TestDNS_Errors, TestDNS_FindAndApex,
//     goipa.TestContractDNSRecords.
//   - Q103: dnsrecord_del removes the given values and the name with its
//     last value; a value the name lacks is 4026 AttrValueNotFound (nothing
//     is removed), del_all removes the name, neither is 3005 OptionError.
//     TestDNS_Errors, goipa.TestContractDNSRecords.
//   - Q143: the apex "@" cannot be deleted: del_all is 3009 "invalid
//     'del_all': Zone record '@' cannot be deleted", and removing its last
//     value keeps it. A missing value is 4026 "<TYPE> record does not contain
//     '<value>'". An absolute name outside the zone is 3009 "invalid
//     'idnsname': out-of-zone data: record name must be a subdomain of the
//     zone or a relative name"; a name without the trailing dot is relative
//     even when it ends in the zone's name, and dnsrecord_add then warns
//     with DNSSuspiciousRelativeName (13014).
//     goipa.TestContractDNSApexAndNames.
//   - Q104: dnsrecord_* in a missing zone, and dnszone_* of one, are 4001
//     NotFound "<zone>: DNS zone not found"; a missing name is 4001 "<name>:
//     DNS resource record not found". goipa.TestContractDNSRecordMissingZone,
//     goipa.TestContractDNSRecords.
//   - Q120: role_show, privilege_show and permission_show (and their _find
//     twins) answer the attributes the ipa types read; a missing object is
//     4001 "<cn>: role not found" (privilege, permission). New servers hold
//     the "User Administrator" role, "User Administrators" privilege and
//     "System: Add Users" permission with FreeIPA 4.13.4's values (4.9.13
//     and 4.12.2 match); attributes outside the ipa types, such as
//     ipapermissiontype and memberindirect_role, are left out. Roles and
//     privileges are not linked: AddRole and AddPrivilege each take their
//     own side. The finds match the criteria against cn and description,
//     the cn option exactly in any case (Q153), and the description and
//     type options exactly.
//     goipa.TestContractRBACBuiltins, goipa.TestContractRBACFind,
//     goipa.TestContractRBACNotFound.
//   - Q121: role_add, role_del and role_add_member are modelled; the latter
//     reports per-member failures with completed and
//     failed.member.{user,group,host,hostgroup,service,idoverrideuser,
//     sysaccount}, sysaccount only from 4.13 on in FreeIPA but always here.
//     Only users, groups and hosts can be added; other kinds fail as "no
//     such entry". goipa.TestContractRoleMembers.
//   - Q122: System: Read Roles, Read Privileges and Read Permissions are
//     bound to the RBAC Readers privilege, so to a caller who is neither uid
//     admin nor in admins role_show, privilege_show and permission_show are
//     4001 and the finds match nothing (roles are not evaluated).
//     goipa.TestContractRBACPlainUser.
//   - Q130: a *_show or *_find command that is neither modelled nor
//     overridden with Handle answers, as its result, the response recorded
//     from a real FreeIPA (ipatest/replay, see SetReplay and NewRecorder)
//     for the greatest recorded release not newer than the SetVersion one,
//     else for the oldest; only without a recording is it 905. The catalogue
//     check runs first, so a command newer than the SetVersion release is
//     905 and an unknown option 3005; beyond that options and arguments are
//     not looked at, so the answer is the same for every call; batch entries
//     are answered the same way. Other commands are never replayed, so an
//     unmodelled write stays 905 instead of faking a change. The shipped
//     recordings come from the integration servers, realm EXAMPLE.TEST and
//     base dc=example,dc=test, while the model answers TEST.LOCAL and
//     dc=test,dc=local, so names and DNs in a replayed answer do not match
//     modelled ones.
//     TestReplay_Precedence, TestReplay_PicksRelease, TestReplay_Disabled,
//     TestReplay_InBatch, TestReplay_IgnoresWrites,
//     TestReplay_CatalogueChecked, TestRecorder_SkipsWrites.
//   - Q60: service principals are stored and reported with the realm
//     (krbcanonicalname and krbprincipalname "svc/host@TEST.LOCAL") and
//     accepted without it. service_add needs the host to exist unless
//     skip_host_check (4001 "The host '<h>' does not exist to add a service
//     to.") and makes it managedby_host; a second add is 4002. With all,
//     ipakrbokasdelegate and ipakrboktoauthasdelegate are false and
//     ipakrbrequirespreauth true. goipa.TestContractServiceLifecycle.
//   - Q61: service_{allow,disallow}_{retrieve,create}_keytab take user,
//     group, host and hostgroup; the grants show as
//     ipaallowedtoperform_{read,write}_keys_<type> unless no_members.
//     goipa.TestContractServiceKeytabAccess.
//   - Q62: a service member call naming a missing member returns the
//     service, completed 0 and failed.<attr>.<type> [[name, "no such
//     entry"]], attr managedby for service_{add,remove}_host and
//     ipaallowedtoperform_{read,write}_keys for the keytab calls.
//     goipa.TestContractServiceMemberMissing,
//     goipa.TestService_KeytabEmptyHostGroup.
//   - Q63: service_add_host of a host already managing the service fails
//     that member ("This entry is already a member"); the host may be
//     removed and added back. goipa.TestContractServiceManagedBy.
//   - Q64: service_disable drops the keys (has_keytab false); a service
//     without keys is 4010 AlreadyInactive "This entry is already
//     disabled". FreeIPA also revokes and removes the certificates its CA
//     issued. Every certificate here comes from service_add_cert (base64
//     DER, returned as {"__base64__": ...}) and is treated as foreign:
//     before 4.13 (SetVersion) such a certificate neither counts nor goes,
//     from 4.13 (seen on 4.13.4, not on 4.12.2) disable removes it and
//     succeeds. FreeIPA 4.13.4 answers 903 to service_disable and
//     service_del of a service holding a certificate without
//     subjectAltName; not modelled.
//     TestService_SeededAndDisable, goipa.TestContractServiceDisable.
//   - Q142: service_add and service_mod take krbprincipalauthind (auth_ind)
//     as an option, and service_mod by setattr, addattr and delattr as in
//     Q41; values outside radius, otp, pkinit, hardened, idp (and passkey
//     from 4.11 on, SetVersion) are 3009 "invalid 'auth_ind': must be one
//     of ..." ('krbprincipalauthind' by attribute). service_show lists them
//     without all; a change that changes nothing is 4202.
//     goipa.TestContractServiceAuthIndicators, TestService_AuthIndVersion.
//   - Q110: automember rules (automember_add, _show, _find, _del) are kept
//     per type, group or hostgroup; another type is 3009 ValidationError
//     "invalid 'type': must be one of 'group', 'hostgroup'". show and del of
//     a missing rule are 4001 "<cn>: Automember rule not found", a second
//     add is 4002, and add needs the target group or host group (4001
//     `<type> "<cn>" not found`). A hostgroup rule is never applied. show
//     and find print dn without all; find's summary is "<n> rules matched".
//     goipa.TestContractAutomemberRule, goipa.TestContractAutomemberMissing,
//     goipa.TestContractAutomemberHostGroup.
//   - Q111: automember_add_condition and _remove_condition on a missing rule
//     are 4001 "Auto member rule: <cn> not found!". They answer completed
//     and failed {"failed": {"automemberinclusiveregex": [...],
//     "automemberexclusiveregex": [...]}}; add skips conditions the rule has
//     without listing them, remove lists the missing ones as "key=regex".
//     With nothing changed the result holds only the regex attributes sent.
//     key is not checked against the schema (FreeIPA answers 4001 "<key> is
//     not a valid attribute."). goipa.TestContractAutomemberRule,
//     goipa.TestContractAutomemberRemoveCondition,
//     goipa.TestContractAutomemberMissing.
//   - Q112: user_add, stageuser_activate (not stageuser_add) and
//     automember_rebuild of type group put a user into every group whose
//     rule has an inclusive condition that matches and no exclusive one
//     that does, or into the default group when no rule matches.
//     Conditions match uid and the attributes User stores under their LDAP
//     names (givenname, sn, title, mail, ...); others never match. Regexes
//     are Go RE2, not the PCRE of 389-ds. Rebuild only adds.
//     goipa.TestContractAutomemberRule, goipa.TestContractAutomemberRebuild,
//     goipa.TestContractAutomemberDefaultGroup,
//     goipa.TestAutomember_StageUserActivate,
//     goipa.TestContractAutomemberStageActivate.
//   - Q113: automember_default_group_show answers automemberdefaultgroup as
//     the group's DN in a list, or the string "No default (fallback) group
//     set". _set of a missing group or host group is 4001 `<type> "<cn>"
//     not found`, of the current one 4202 EmptyModlist; _remove with none
//     set is 4001 "No default (fallback) group set".
//     goipa.TestContractAutomemberDefaultGroup,
//     goipa.TestContractAutomemberHostGroup.
//   - Q114: automember_del deletes the rules named before the first missing
//     one, then fails with 4001. goipa.TestContractAutomemberMissing.
//   - Q80: sudorule_enable and sudorule_disable succeed with {"result":
//     true} whatever the rule's state, so a second call is no error (FreeIPA
//     swallows EmptyModlist). goipa.TestContractSudoRuleEnableTwice.
//   - Q81: the sudo rule member calls keep names FreeIPA does not know as
//     external members, lower-cased and counted in completed: users and
//     groups in externaluser, hosts in externalhost, run-as users and
//     groups in ipasudorunasextuser and ipasudorunasextusergroup, run-as
//     groups in ipasudorunasextgroup. Only missing host groups, commands
//     and command groups fail with "no such entry"; command groups are not
//     modelled, so each one fails. Removing a name that is
//     neither a member nor external, existing or not, is "This entry is not
//     a member".
//     goipa.TestContractSudoRuleExternalMembers,
//     goipa.TestContractSudoRuleMemberMissing, TestSudoMember_External,
//     TestSudoMember_HostGroup.
//   - Q82: sudorule_add_option of an option the rule has is 4002
//     "This entry already exists" and changes nothing; sudorule_remove_option
//     of one it lacks is 4026 "ipasudoopt does not contain '<option>'".
//     sudocmd_add and sudocmd_del keep only the command and its description;
//     FreeIPA's refusal to delete a command a rule uses is not modelled.
//     goipa.TestContractSudoRuleOptions, TestSudoCmd_AddDel.
//   - Q83: at a 4.9 release sudorule_add_option and sudorule_remove_option
//     reject any JSON list for ipasudoopt, even of one value, with 3008
//     "invalid 'ipasudoopt': Only one value is allowed", although the schema
//     marks it multivalued; 4.12.2 and later take a list. Releases between
//     are not pinned and take a list. goipa's SudoRuleAddOption and
//     SudoRuleRemoveOption send one scalar call per option.
//     goipa.TestContractSudoRuleOptions,
//     TestSudoOption_ListAt49.
//   - Q150: the default HBAC service groups hold FreeIPA's members: Sudo
//     sudo and sudo-i, ftp ftp, gssftp, proftpd, pure-ftpd and vsftpd.
//     goipa.TestContractHBACTestServiceGroup.
//   - Q151: sudorule_add and sudorule_mod of a sudoorder another rule holds
//     are 3009 "invalid 'order': order must be a unique value (<n> already
//     used by <cn>)", checked before the name on add. sudorule_mod is
//     modelled for description and sudoorder only (any other option is
//     905); a rule's own order, like no change at all, is 4202.
//     goipa.TestContractSudoOrderUnique, TestSudoRuleMod_UnmodelledOption.
//   - Q152: as Q73 for sudo rules: adding to a rule whose category is all
//     is 4303 "users cannot be added when user category='all'" (hosts/host,
//     "commands cannot be added when command category='all'" for allowed
//     commands, and "users cannot be added when runAs user or runAs group
//     category='all'" for run-as users and run-as groups when either run-as
//     category is all). Denied commands are not checked.
//     goipa.TestContractSudoRuleCategoryConflict.
//   - Q153: role_find, privilege_find and permission_find match the cn
//     option against the whole name, ignoring case ("user administrator"
//     finds the role, "User Adm" none), the criteria as a substring.
//     goipa.TestContractRBACFindCNExact.
//   - Q154: otptoken_del by a caller who is neither uid admin nor in admins
//     is 2100 "Insufficient access: " for a token that does not exist and
//     "Insufficient access: Insufficient 'delete' privilege to delete the
//     entry 'ipatokenuniqueid=<id>,cn=otp,dc=test,dc=local'." for another
//     user's, on 4.9.13, 4.12.2 and 4.13.4 alike.
//     goipa.TestContractOTPDeleteAsUser.
//   - Q155: session_logout does not end the session on the server: the
//     reply only deletes the client's cookie (Q39), and the old cookie sent
//     again keeps working as before. ExpireSession is the way to end one.
//     goipa.TestContractStaleSessionCookie.
//
// A response's version is the server release, 4.13.4 unless SetVersion
// changes it, and its principal is
// <uid>@TEST.LOCAL. An error a HandlerFunc returns without a Name gets the
// FreeIPA name for its code.
//
// # Not modelled
//
// Certificates are issued (cert_request, cert_show, cert_revoke) for service
// principals only, with the default profile; user and host certificates,
// other profiles, sub-CAs, cert_find and the other cert commands are left
// out, as is host_add's DNS check (every fqdn is accepted, as with force).
// The *_mod commands of the families modelled since v0.9 (host groups,
// services, HBAC and sudo rules, DNS, automember, RBAC) are not modelled
// (sudorule_mod only for description and sudoorder, Q151), nor are role,
// privilege and permission changes other than role_add,
// role_del and role_add_member, HBAC services and service groups, or sudo
// command groups; Handle is the way to reach the rest, as for config_*,
// subid_show, stageuser_add_passkey and stageuser_remove_passkey.
// Of DNS, only master zones and the record commands above: dnszone_add
// ignores its SOA, TTL and policy options and the name server and overlap
// checks, serials do not move, record values are neither validated nor
// normalised, a CNAME may share a name with other records, and dnsrecord_find
// filters by criteria and idnsname only.
// Stage user passwords are not modelled: userpassword is ignored and random
// behaves as for active users. Kerberos, LDAP search filters, size limits on
// other commands, replication and HTTP fault injection are left out; wrap
// HTTPClient's transport for the latter.
package ipatest
