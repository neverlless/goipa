# goipa ChangeLog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (v0.x: minor releases may add API,
existing exported identifiers keep their signatures).

## [Unreleased]

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

[Unreleased]: https://github.com/neverlless/goipa/compare/v0.5.0...HEAD
[v0.5.0]: https://github.com/neverlless/goipa/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/neverlless/goipa/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/neverlless/goipa/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/neverlless/goipa/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/neverlless/goipa/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/neverlless/goipa/releases/tag/v0.1.0
