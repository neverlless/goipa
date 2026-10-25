# goipa ChangeLog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (v0.x: minor releases may add API,
existing exported identifiers keep their signatures).

## [Unreleased]

The v1 API freeze: from v1.0.0 no exported identifier of `ipa` or `ipatest`
is removed or re-signed (see Stability in the README). This release marks
what newer identifiers supersede, fixes the last client-side bugs found in
the API review and makes `ipatest` follow FreeIPA more closely.

### Deprecated

- `NewDefaultClient`, `NewDefaultClientWithSession`, `NewClient` and
  `NewClientCustomHttp` (use `New`), `DefaultTOTPToken` (use `AddOTPToken`
  with nil), `ParseDateTime` (use `Entry.Time`) and `Response.Error`. All
  keep working.

### Changed

- Wire-equivalent shape changes, visible in `ipatest.Calls()`:
  `hbacrule_del` and `dnszone_del` send `continue: false`;
  `hostgroup_find` and `otptoken_find` with no criteria send `[""]` as the
  argument
- `Entry.Strs` returns a lone hint object other than `__dns_name__` as its
  JSON instead of its inner value, as it already did inside a list
- A 401 from `SetPassword` and `SyncOTPToken` now also matches
  `ErrUnauthorized`; failures of `RemoteLogin`, `SetPassword` and
  `SyncOTPToken` match `*HTTPError` with `errors.As`, message text unchanged
- With `WithValidation`, an option key that names a positional argument newer
  than the server gives `ErrNotSupported`
- `ipatest`: new getters `HBACRule`, `SudoRule`, `PwPolicy`, `Role`,
  `Privilege` and `Permission`, and `Service.AuthIndicators`
- `ipatest` behaviour (see Q140 to Q155 in the package documentation):
  `host_del` deletes the host's services; host group cycles are accepted;
  `service_mod` and `krbprincipalauthind`; `sudoorder` must be unique and
  sudo rules reject member lists that conflict with a category; `hbactest`
  expands the default HBAC service groups; RBAC `cn` finds match the whole
  name; `otptoken_del` by a non-admin gives 2100; certificate principals are
  case-sensitive and a second revoke fails; DNS apex and name checks;
  `session_logout` does not end the session, as on real servers (Q155), and
  a missing session gets FreeIPA's HTML 401 page

### Fixed

- A goroutine waiting for another's password re-login returns `ctx.Err()`
  when its context ends instead of blocking
- `ClearSession` during a re-login is no longer undone by the login that was
  already in flight
- Command catalogue generator: `autofill` is read only as a keyword argument,
  a stale allow-list entry and two source files for one version are errors

### Security

- On FreeIPA 4.9 to 4.13 the server keeps accepting a session cookie after
  `session_logout`. Logout only makes the client forget it, so treat a
  session ID as a credential until it expires. Documented in the README and
  the package documentation.

## [v0.9.1] - 2026-10-24

### Fixed

- `ipatest`: host group names are matched case-insensitively in rules,
  services, automember rules and nested groups, as in FreeIPA, and are
  reported lower-cased

## [v0.9.0] - 2026-10-24

Typed objects: host groups, services and keytab access, HBAC and sudo rule
management, certificates, DNS zones and records, automember rules, and
roles, privileges and permissions, each with an `ipatest` model and contract
tests checked against real FreeIPA 4.9, 4.12 and 4.13. `ipatest` also
answers commands it does not model with responses recorded from those
servers.

### Added

- Host groups: `HostGroupShow`, `HostGroupFind`, `HostGroupAdd`,
  `HostGroupDelete`, member and member-manager calls
- Services: `ServiceShow`, `ServiceFind`, `ServiceAdd`, `ServiceDelete`,
  `ServiceDisable`, hosts that manage a service, and the keytab access lists
  (`ServiceAllowRetrieveKeytab` and its three siblings with `KeytabAccess`)
- HBAC and sudo rules: show, add, delete, enable, disable and members
  (`HBACRuleAddUser`, `SudoRuleAddAllowCommand`, `SudoRuleAddRunAsUser`,
  `SudoRuleAddOption`, ...); `SudoRule.RunAsUserGroups`
- Certificates: `CertRequest`, `CertShow`, `CertRevoke`
- DNS: zones (`DNSZoneShow`, `DNSZoneFind`, `DNSZoneAdd`, `DNSZoneDelete`,
  `DNSZoneEnable`, `DNSZoneDisable`) and records (`DNSRecordShow`,
  `DNSRecordFind`, `DNSRecordAdd`, `DNSRecordRemove`, `DNSRecordDelete`)
- Automember rules: show, find, add, delete, conditions, default group,
  rebuild (`AutomemberShow`, `AutomemberAddCondition`, `AutomemberRebuild`, ...)
- Roles, privileges and permissions, read only: `RoleShow`/`RoleFind`,
  `PrivilegeShow`/`PrivilegeFind`, `PermissionShow`/`PermissionFind`
- Every new call has a `...Context` twin. Attribute changes go through
  `Modify` (for automember, `RPC`, since it needs the rule type); member
  calls return the updated object and a `*MemberError` for members the
  server refused
- `ipatest`: models for all of the above, with `AddHostGroup`, `AddService`,
  `AddRole`, `AddPrivilege` and `AddPermission` seed helpers (`AddHBACRule`
  and `AddSudoRule` exist since v0.5.0)
- `ipatest`: `NewRecorder` records a real server's `*_show`/`*_find`
  responses (secrets redacted) and `Server.SetReplay` answers from them; the
  recordings of FreeIPA 4.9.13, 4.12.2 and 4.13.4 are embedded, so tests of
  commands goipa does not wrap see real response shapes. `IPATEST_RECORD=dir`
  records during the contract tests

### Changed

- `ipatest`: `host_add` and `host_del` are modelled; `host_del` and
  `hostgroup_del` remove the deleted entry from host groups, HBAC and sudo
  rules and services that named it
- `ipatest`: `sudorule_add_user` (and the other sudo member calls) with
  unknown users, groups or hosts now succeeds, keeping them as external
  members as FreeIPA does; a duplicate `sudorule_add_option` is 4002
- `ipatest`: commands that are not modelled are checked against the
  catalogue too, so an unknown option is 3005 before the 905 or replayed
  answer
- `ipatest`: a `*_show` or `*_find` command that is not modelled and has no
  `Handle` override is answered from the recordings instead of 905 (a
  built-in or a `Handle` override still wins); `SetReplay(nil)` restores 905.
  The recordings add about 3 MB to the `ipatest` package only
- The integration CI container installs FreeIPA with integrated DNS

### Notes from the real servers

Checked on FreeIPA 4.9.13, 4.12.2 and 4.13.4; `ipatest` follows them
(quirks Q50 to Q139 in its documentation).

- Enabling or disabling an HBAC rule, sudo rule or DNS zone twice succeeds
- The default certificate profile accepts RSA keys only; an ECDSA CSR fails
- On 4.9 `sudorule_add_option` takes one option per request, so
  `SudoRuleAddOption` sends them one at a time
- A sudo rule's unknown users, groups and hosts become external members

## [v0.8.0] - 2026-10-24

Command catalogue: every command, argument and option of FreeIPA 4.9.0 to
4.13.4, with the release that introduced each, generated from FreeIPA's own
`API.txt`. Clients can opt in to checking every call against it before it
is sent. Checked against real FreeIPA 4.9, 4.12 and 4.13 by the contract
tests, which now run with validation on.

### Added

- `Commands`, `LookupCommand`, `Command` and `Param`: the FreeIPA command
  catalogue for releases 4.9.0 to 4.13.4 (positional arguments, options,
  types and the release that introduced each), generated from `API.txt` with
  `go generate`; a nightly CI job fails when it is out of date
- `WithValidation` and `ErrInvalidCall`: opt-in check of every call against
  the catalogue before it is sent, including each call inside `Batch`;
  commands and options newer than the server give `ErrNotSupported`
- `ipatest`: built-in commands reject options the command lacks at the
  reported release (`OptionError`) and commands added after it;
  `passkeyconfig_show` is modelled

### Changed

- `ipatest`: built-in commands now reject options they lack and commands
  newer than the `SetVersion` release (3005 / 905), so consumer tests that
  sent such options may fail on upgrade; `SetVersion` now affects behaviour,
  not only the reported string. `Handle` overrides are not checked

## [v0.7.0] - 2026-10-24

Typed escape hatch and core API: any FreeIPA command can be called with
typed decoding, truncated searches are reported, attributes can be changed
one at a time, several commands can run in one round trip, and calls for
features newer than the server fail early. Checked against real FreeIPA
4.9, 4.12 and 4.13 by the contract tests.

### Added

- `Call[T]`, a generic typed call for any FreeIPA command, and `Entry`, a
  result object with `Has`, `Str`, `Strs`, `Bool`, `Int`, `Time`, `Bytes`,
  `DN` and `Raw` accessors that read FreeIPA's attribute lists,
  `__datetime__` and `__base64__` values
- `FindEntries(ctx, c, method, args, opts, sizelimit)` and `ErrTruncated`:
  a `*_find` that reports a result truncated by the server's size limit
  instead of returning it silently
- `ServerVersion` and `ErrNotSupported`: passkey calls (FreeIPA 4.11) and
  `SubIDFind`/`SubIDGenerate` (4.9.7) fail before sending when the known
  server is older
- `Modify(command, keys...)`: `setattr`/`addattr`/`delattr` updates of
  single attributes on any object, nested ones included
- `Batch`: several commands in one round trip with per-command results;
  `BatchResult.Err` is an `error` holding a bare `*IpaError`
- `CodeConversion` (3008), `CodeObjectclassViolation` (4205) and `CodeOnlyOneValueAllowed` (4207)
- `ipatest`: `SetVersion`, `sizelimit` truncation on `user_find`,
  `group_find` and `host_find`, `setattr`/`addattr`/`delattr` on `user_mod`
  and `stageuser_mod` (including `OnlyOneValueAllowed`), and `batch`

## [v0.6.0] - 2026-10-24

Construction and authentication: an options-based `New` with no file I/O at
import time, Kerberos login from memory, `WhoAmI`, and recovery from expired
sessions. The session behaviour is checked against real FreeIPA 4.9, 4.12
and 4.13 by the contract tests.

### Added

- `New(opts ...Option) (*Client, error)` with `WithHost`, `WithRealm`,
  `WithCACert`, `WithHTTPClient`, `WithKrb5Config`, `WithKrb5ConfigData` and
  `WithPasswordRelogin`. The old constructors keep their signatures
- `LoginWithKeytabData`, `LoginFromCCacheData` and in-memory Kerberos
  configuration (`WithKrb5ConfigData`; idea from sitnikovv's fork), for
  containers and secret stores
- `WhoAmI` and `WhoAmIContext`
- Expired sessions are recovered: Kerberos clients retry once through
  SPNEGO; with `WithPasswordRelogin`, `RemoteLogin` clients log in again
  and retry once (a password FreeIPA rejects is forgotten; needs sticky
  sessions; concurrent 401s cost one login). Other clients get
  `ErrUnauthorized` and the session is cleared
- `ipatest.Server.CACert`, and `whoami` and `session_logout` in `ipatest`
- "Which login to use" guide in the README and package documentation

### Changed

- A 401 on a session request now clears the session (it was kept)
- Clients with a Kerberos login, old constructors included, retry once
  through SPNEGO after a 401
- `NewDefaultClient*`, `NewClient` and `New` read `/etc/ipa` on first use
  instead of at import; `NewClientCustomHttp` never reads it
- `ClearSession` also forgets the credentials kept by `WithPasswordRelogin`
- FreeIPA's logout cookie (an `ipa_session` cookie that deletes the session,
  or `MagBearerToken=`) clears the session; before, `session_logout` failed
  with "invalid set-cookie header"

## [v0.5.0] - 2026-10-24

Account lifecycle and access: stage users, lockout status and unlock,
password policy, subordinate IDs, HBAC and sudo rules with hbactest,
passkey mappings and OTP token sync, each with a `Context` twin and an
`ipatest` model. Every behaviour is checked against real FreeIPA 4.9,
4.12 and 4.13 by the contract tests.

- Stage users: `StageUserAdd`, `StageUserShow`, `StageUserFind`,
  `StageUserMod`, `StageUserActivate` and `StageUserDelete`
- Lockout: `UserStatus` returns one `ReplicaStatus` per master (failed
  logins in either of FreeIPA's forms, last success and failure times, an
  unreachable master reported instead of failing the call); `UserUnlock`
- Password policy: `PwPolicyShow` and `UserPwPolicy`, with durations as
  `time.Duration` and the FreeIPA 4.13 password-quality credits and grace
  login limit
- Subordinate IDs: `SubIDFind` and `SubIDGenerate`
- HBAC and sudo: `HBACRuleFind`, `SudoRuleFind` and `HBACTest`, which
  reads hbactest's result correctly and evaluates every rule, not only the
  first 100
- Passkeys: `UserAddPasskey` and `UserRemovePasskey`
- `SyncOTPToken` and `ErrInvalidCredentials` (based on ubccr/goipa#2 by
  @farzandalaee)
- `CodeOption` (3005 OptionError: an option the command does not take)
- `ipatest` models stage users, user_status and user_unlock, password
  policies, sub-IDs, HBAC and sudo rules (with the default `allow_all`
  rule), hbactest, passkey mappings and token sync

## [v0.4.0] - 2026-10-23

Users and groups: typed group management with per-member failures as
errors, all of a user's mail addresses, address, language and passkeys,
and host lookups. Every behaviour is checked against real FreeIPA 4.9,
4.12 and 4.13 by the contract tests.

- Groups: `GroupShow`, `GroupFind`, `GroupAdd`, `GroupMod`, `GroupDelete`,
  `GroupAddMember`, `GroupRemoveMember`, `GroupAddMemberManager` and
  `GroupRemoveMemberManager`, each with a `Context` twin. Per-member
  failures, including insufficient access, are returned as `*MemberError`
  (FreeIPA reports them with no error); the updated group is returned with
  it. Based on ubccr/goipa#9 by @earthquakesan, #14 by @ivanovilia96 and
  #17 by @m-vinc
- `User.Emails` (all `mail` values, ubccr/goipa#10), `IndirectGroups`
  (from `user_show`; idea from fajo-de), `Street`, `City`, `State`,
  `PostalCode`, `PreferredLanguage`, `Title`, `OrgUnit` (title/ou as in
  tubby1981's fork) and `Passkeys`. These are read-only: `UserMod` does
  not write them
- `HostShow` and `HostFind` (ubccr/goipa#11)
- `ipatest` models groups, member managers, nested groups, hosts and the
  new user attributes in FreeIPA's response shapes; contract tests pin
  them against the real server in the nightly run
- `UserMod` dropped every `mail` value but the first. `Email` is still the
  first address and replaces it; the rest of `Emails` is kept. A single
  address is sent exactly as before
- `SetPassword` no longer posts an empty `otp` field; `randompassword` is
  read whether the server returns a string or a list (both found by
  tubby1981)

## [v0.3.0] - 2026-10-23

Test infrastructure: an in-memory FreeIPA server for unit tests, and the
same contract tests run nightly against real FreeIPA 4.9, 4.12 and 4.13.
The first real-server runs found a bug in `UserAdd` that dates back to
ubccr/goipa v0.0.7; it is fixed here.

- New package `ipatest`: a fake FreeIPA server over TLS for tests of code
  that uses goipa. `NewServer(t)` (or `New()` outside tests), `Client`,
  `ClientAs`, `Session`, seed and inspect users and OTP tokens, a call
  log (`Calls`) and `Handle` to inject errors or serve any command it
  does not model. It models user_show/find/add/mod/del/disable/enable,
  passwd, otptoken_add/del/mod/find, login_password and change_password
  with the lockout, expiry and last-OTP-token behaviour of FreeIPA 4.13;
  each quirk is listed in the package doc and pinned by a test
- `(*IpaError).MarshalJSON` writes FreeIPA's error shape
  (`code`, `message`, `name`, `data`); `Data` that is not JSON becomes `{}`
- Unit tests for the whole API against `ipatest`, coverage above 80 %
  (gated in CI) and Codecov upload
- Integration tests run nightly against FreeIPA 4.9.13, 4.12.2 and 4.13.4;
  the same contract tests run against `ipatest` and the real server. The
  integration tests are now named `*_integration_test.go`
- pkg.go.dev examples for the login modes and the `RPC` escape hatch
- Removed the CentOS 7 `container/`, `docker-compose.yml` and `.env.sample`;
  `scripts/ipa-up.sh` starts a FreeIPA container instead
- Testing with `ipatest`: it answers `/ipa/json` (the Kerberos endpoint)
  with 401 unless `SetNegotiateUser` is set, as a real server does for a
  client without a Kerberos ticket; log in with `RemoteLogin` or `ClientAs`
  instead
- `UserAdd` and `UserAddWithPassword` leave empty attributes out of
  user_add, so FreeIPA applies its defaults; an unset `HomeDir` failed
  with 4205 missing attribute "homeDirectory" (bug since v0.0.7)
- `ipatest`: JSON-RPC without a valid Referer gets HTTP 400 text/html like
  FreeIPA, not error 911; a `MagBearerToken` it did not issue closes the
  connection (goipa returns EOF), as the real server's httpd crashes on it
- `ipatest` models user_add with an empty homedirectory (4205, Q19)
- `ipatest.Server.ExpireSession` ends a session; calls with it get 401
  (`ErrUnauthorized`), as for an expired session on FreeIPA
- `scripts/ipa-up.sh` sets `forwardable = true` in krb5.conf; without it
  every Kerberos call fails 2100 "Credential cache is empty"
- Contract tests expect invalid-password for locked users before FreeIPA
  4.13.1 (FreeIPA issue 9891)

## [v0.2.1] - 2026-10-23

- Keytab, password and ccache logins work on ipa-client 4.13 hosts
  (RHEL / CentOS Stream 9 and 10). ipa-client-install 4.13 moves
  `[realms]` to `/etc/krb5.conf.d/freeipa-realm` and leaves only
  `includedir` in krb5.conf, which gokrb5 ignores, so logins failed with
  `lookup _kerberos._tcp.<REALM> ... no such host` unless the realm had
  DNS SRV records
- `include` and `includedir` in krb5.conf are now resolved as MIT krb5
  does: single values take the first definition, a realm defined in
  several files keeps all its `kdc` entries, and only file names MIT
  accepts are read from an includedir. A missing include file or
  includedir is skipped, as before. A krb5.conf without include
  directives is parsed exactly as before

## [v0.2.0] - 2026-10-23

A generic `RPC` call for any FreeIPA command, typed errors and
`context.Context` support. All changes are additive: code written for
v0.1.0 or ubccr/goipa v0.0.7 compiles unchanged, and CI now enforces that.

- `(*Client).RPC` and `RPCContext` call any FreeIPA command with the
  client's TLS settings, session or Kerberos auth and API version
  (ubccr/goipa#11)
- `Result` keeps `Count`, `Truncated`, `Messages`, `Completed`, `Failed`
  and the whole result object in `Raw` (for shapes without a `result` key
  such as `hbactest`)
- FreeIPA error code constants (`CodeNotFound`, ...), `IpaError.Name` and
  `IpaError.Data`, and `errors.Is(err, ipa.ErrNotFound)` (also
  `ErrDuplicateEntry`, `ErrACI`, `ErrEmptyModlist`). Errors are still a
  bare `*IpaError`, so `err.(*ipa.IpaError)` keeps working
- `errors.Is` between two `*IpaError` values matches by `Code`, not by
  pointer identity
- A `"version"` in the caller's `Options` is sent as is (it was always
  overwritten with `IpaClientVersion`)
- Non-200 JSON-RPC responses return `*HTTPError`; HTTP 401 (e.g. an
  expired session) matches `errors.Is(err, ipa.ErrUnauthorized)`. The
  message text is unchanged
- `SetSessionID` restores a saved session on any client
- `...Context` twins of every method that talks to the server
  (`PingContext`, `RemoteLoginContext`, `UserShowContext`,
  `AddOTPTokenContext`, ...). Kerberos `Login*` have none: gokrb5 cannot
  be cancelled
- `rpc` and `UserFind` no longer write `version`/`all`/`no_members` into
  the caller's `Options` map (data race when shared)
- A response without `result` and `error` is an error instead of a
  nil-pointer panic
- Responses over 64 MiB are rejected
- `AddOTPToken` no longer writes defaults into `DefaultTOTPToken` (data
  race) or into the token passed in; it sends `NotBefore`/`NotAfter` in
  UTC (they were sent in the caller's zone with a `Z` suffix)
- Logging in again on the same `Client` destroys the previous Kerberos
  client instead of leaking its renewal goroutine and credentials
- Package documentation on pkg.go.dev: login modes, concurrency, errors,
  context support
- `gjson` 1.17.1 → 1.20.0; test-only `testify`, `godotenv` and `gofakeit`
  updated (#1)
- CI fails on any incompatible API change against the latest tag (apidiff)

## [v0.1.0] - 2026-10-22

First release of the maintained continuation of
[ubccr/goipa](https://github.com/ubccr/goipa). The API is the same as
ubccr/goipa v0.0.7; only the import path changes:

```sh
grep -rl ubccr/goipa --include='*.go' . | xargs sed -i 's#ubccr/goipa#neverlless/goipa#'
go mod tidy
```

- Module path is now `github.com/neverlless/goipa`
- **goipa no longer logs, and no longer depends on logrus.** At logrus
  `trace` level it dumped every request and response, which wrote the old
  and new password and OTP from `ChangePassword`, the random password from
  `ResetPassword` and `UserAdd`, and session cookies into the caller's log
  (in mokey: whenever `--log-level trace` was set). No exported API
  changes. To debug, wrap the transport of the `http.Client` passed to
  `NewClientCustomHttp` and log metadata only
- `golang.org/x/crypto` 0.23.0 → 0.58.0, with `x/net` and `x/sys`. Fixes
  GO-2026-5018; supersedes ubccr/goipa#18 (0.31.0 was no longer enough)
- `ErrUserExists` had the message `"unauthorized"`, the same as
  `ErrUnauthorized`. Its message is now `"user exists"`. Callers using
  `errors.Is` are unaffected (reported in ubccr/goipa#14 by @ivanovilia96)
- A response that set another cookie before `ipa_session` (for example a
  load balancer's) failed with "invalid set-cookie header" after the server
  had already run the command, so a successful `ResetPassword` or `UserAdd`
  lost its random password. Cookies other than `ipa_session` are ignored
- A `Client` can be shared between goroutines: the session ID, sticky flag
  and Kerberos client are guarded by a mutex. They used to be a data race
- A Kerberos (SPNEGO) failure while building a request is returned as an
  error. It used to be ignored, so the request went out unauthenticated and
  failed as `ErrUnauthorized`
- Errors from building HTTP requests in `rpc`, `RemoteLogin` and
  `SetPassword` are returned instead of being ignored
- "Username is required" errors from `UserAdd`, `UserAddWithPassword` and
  `UserMod` start with a lowercase letter, per Go conventions
- Minimum Go version is 1.26
- Tests that need a real FreeIPA server moved behind the `integration` build
  tag, and the ones that no longer compiled were fixed, so `go test ./...`
  passes without a server
- CI: gofmt, go vet, `go test -race`, govulncheck, staticcheck and gosec on
  every push and pull request; Dependabot for Go modules and GitHub Actions

## Upstream releases

v0.0.1 – v0.0.7 were released by Andrew E. Bruno as
[ubccr/goipa](https://github.com/ubccr/goipa/tags). This repository keeps
that history.

[Unreleased]: https://github.com/neverlless/goipa/compare/v0.9.1...HEAD
[v0.9.1]: https://github.com/neverlless/goipa/compare/v0.9.0...v0.9.1
[v0.9.0]: https://github.com/neverlless/goipa/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/neverlless/goipa/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/neverlless/goipa/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/neverlless/goipa/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/neverlless/goipa/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/neverlless/goipa/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/neverlless/goipa/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/neverlless/goipa/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/neverlless/goipa/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/neverlless/goipa/releases/tag/v0.1.0
