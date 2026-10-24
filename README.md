# goipa

**Go client library for the FreeIPA / Red Hat IdM JSON-RPC API.**

[![CI](https://github.com/neverlless/goipa/actions/workflows/ci.yml/badge.svg)](https://github.com/neverlless/goipa/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/neverlless/goipa/branch/main/graph/badge.svg)](https://codecov.io/gh/neverlless/goipa)
[![Go Reference](https://pkg.go.dev/badge/github.com/neverlless/goipa.svg)](https://pkg.go.dev/github.com/neverlless/goipa)
[![Release](https://img.shields.io/github/v/release/neverlless/goipa)](https://github.com/neverlless/goipa/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/neverlless/goipa)](go.mod)
[![License](https://img.shields.io/github/license/neverlless/goipa)](LICENSE)

goipa talks to a [FreeIPA](https://www.freeipa.org/) server over HTTPS using
its JSON-RPC [API](https://github.com/freeipa/freeipa/blob/master/API.txt).
It logs in with a password, a keytab, a Kerberos credential cache or an
existing session, and gives you typed Go calls for users, stage users, groups
with their members and member managers, hosts, passwords and lockout,
password policy, sub-IDs, HBAC/sudo rules and hbactest, passkeys and OTP
tokens.

> **Note:** This is the maintained continuation of
> [ubccr/goipa](https://github.com/ubccr/goipa) by Andrew E. Bruno, which has
> had no release since 2024. It is a drop-in replacement for ubccr/goipa
> v0.0.7; see [Migrating from ubccr/goipa](#migrating-from-ubccrgoipa).
> It is developed alongside [mokey](https://github.com/neverlless/mokey), a
> FreeIPA self-service portal.

## Features

- Login: password (`Login`, `RemoteLogin`), keytab (`LoginWithKeytab`,
  `LoginWithKeytabData`), Kerberos credential cache (`LoginFromCCache`,
  `LoginFromCCacheData`), or a saved session ID
  (`NewDefaultClientWithSession`); see [Which login to use](#which-login-to-use)
- Kerberos clients recover expired sessions; password re-login is opt-in
  (`WithPasswordRelogin`); `WhoAmI`
- Reads the host, realm and CA from `/etc/ipa/default.conf` and
  `/etc/ipa/ca.crt` on enrolled machines, or takes them explicitly
  (`New` with `With*` options, `NewClient`, `NewClientCustomHttp`)
- Users: show, find, add (with random or given password), modify, enable,
  disable, delete
- Passwords: set, change (with OTP), reset; typed errors for policy, invalid
  and expired passwords
- SSH public keys and user authentication types (password, OTP, ...)
- OTP tokens: add, list, enable, disable, remove, sync (`SyncOTPToken`)
- Stage users: add, show, find, modify, activate, delete
  (`StageUserAdd`, `StageUserActivate`, ...)
- Groups: show, find, add, modify, delete; members and member managers
  (`GroupAddMember`, `GroupAddMemberManager`, ...), with per-member failures
  returned as `*MemberError`
- Hosts: show, find (`HostShow`, `HostFind`)
- Lockout: per-replica failed logins and unlock (`UserStatus`, `UserUnlock`)
- Password policy: group, global and effective per user (`PwPolicyShow`,
  `UserPwPolicy`)
- Sub-IDs: find, generate (`SubIDFind`, `SubIDGenerate`)
- HBAC and sudo: rule lookups and access checks (`HBACRuleFind`,
  `SudoRuleFind`, `HBACTest`)
- Passkeys: add, remove (`UserAddPasskey`, `UserRemovePasskey`)
- Typed errors: `errors.Is(err, ipa.ErrNotFound)` and friends; server errors
  are a bare `*IpaError` with `Code`, `Name` and `Data`
- A `…Context` variant of every call that talks to the server (the Kerberos
  logins excepted)
- `RPC` / `RPCContext` for any other command, reusing the client's TLS
  config, session or Kerberos auth and API version
- `Call[T]` and `Entry`: typed decoding of any command's result, with
  accessors for FreeIPA's attribute lists, dates and binary values
- `FindEntries` returns `ErrTruncated` when the server cut a search short
- `Modify` changes single attributes (`setattr`/`addattr`/`delattr`) on any
  object; `Batch` sends several commands in one round trip
- `ServerVersion`; passkey and sub-ID calls return `ErrNotSupported` when the
  server is known to be older than FreeIPA 4.11 and 4.9.7
- [`ipatest`](https://pkg.go.dev/github.com/neverlless/goipa/ipatest), a fake
  FreeIPA server for your own tests

See the [roadmap](ROADMAP.md) for what is next.

## Command catalogue and validation

`Commands(version)` and `LookupCommand(name, version)` list every FreeIPA
command from 4.9.0 up to the newest catalogued release (4.13.4): positional
arguments, options with their types, and the release that introduced each.
An empty version means everything. The data is generated from FreeIPA's
`API.txt`; `go generate ./...` refreshes it, and a nightly CI job fails when
a new release adds something the catalogue lacks.

```go
c, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"), ipa.WithValidation())
// ...
_, err = c.RPC("user_show", []string{"jesse"}, ipa.Options{"no_such_option": true})
errors.Is(err, ipa.ErrInvalidCall) // true, nothing was sent
```

`WithValidation` is off by default. It rejects unknown commands, too many
positional arguments and unknown options (`ErrInvalidCall`), and commands or
options newer than the server (`ErrNotSupported`), for typed methods, `RPC`,
`Call`, `FindEntries` and every call inside `Batch`. It does not check values
or required options, and it is skipped when the server is newer than the
catalogue. Validation is opt-in through `New` only (the old constructors
never validate), and an option key that names a positional argument is
accepted. The server version comes from the replica that answered last, so in
a mixed 4.9/4.13 fleet behind a load balancer a call valid on 4.13 can get
`ErrNotSupported`; `Since` values are upstream releases, so distro backports
are not known.

For its built-in commands `ipatest` rejects options the command lacks at the
`SetVersion` release (3005 `OptionError`, `Unknown option: <name>`) and
commands added after that release (905). It does not count arguments or
return `ErrNotSupported`, and `Handle` overrides are not checked.

## Install

```sh
go get github.com/neverlless/goipa
```

Requires Go 1.26 or newer. The package name is `ipa`.

## Usage

On a host enrolled in FreeIPA (with `/etc/ipa/default.conf`), log in with a
keytab and show a user:

```go
package main

import (
	"fmt"
	"log"

	ipa "github.com/neverlless/goipa"
)

func main() {
	client := ipa.NewDefaultClient()

	if err := client.LoginWithKeytab("/etc/myapp/myapp.keytab", "myapp"); err != nil {
		log.Fatal(err)
	}

	user, err := client.UserShow("jdoe")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s <%s> uid=%s groups=%v\n", user.DisplayName, user.Email, user.Uid, user.Groups)
}
```

Elsewhere, name the server and realm and log in with a password:

```go
client := ipa.NewClient("ipa.example.com", "EXAMPLE.COM")
if err := client.RemoteLogin("jdoe", password); err != nil {
	switch {
	case errors.Is(err, ipa.ErrExpiredPassword):
		// ask for a new password, then client.SetPassword(...)
	case errors.Is(err, ipa.ErrInvalidPassword):
		// wrong password
	}
}
// Keep client.SessionID() and reuse it later with NewDefaultClientWithSession.
```

## Which login to use

| Method | How it authenticates | Needs | Use when |
|---|---|---|---|
| `RemoteLogin` | password over HTTPS (`/ipa/session/login_password`) | the CA; no Kerberos | web apps, scripts, hosts not enrolled |
| `Login` | password through the KDC (Kerberos) | krb5.conf (`WithKrb5Config*`), realm | you have a password and want a ticket |
| `LoginWithKeytab` / `LoginWithKeytabData` | keytab | krb5.conf, realm | services, daemons |
| `LoginFromCCache` / `LoginFromCCacheData` | an existing ticket cache (kinit) | krb5.conf | CLI tools run by a logged-in user |
| saved session (`SetSessionID`, `NewDefaultClientWithSession`) | the `ipa_session` cookie | none | restoring a web session |

`Login` is Kerberos, not the web login: it needs a KDC and a krb5.conf. To
log in with a password over HTTPS, use `RemoteLogin`.

When a session expires (HTTP 401), the call is retried once:

- Kerberos clients (`Login`, `LoginWithKeytab*`, `LoginFromCCache*`) clear the
  session and retry through SPNEGO. If another goroutine has already got a
  fresh session, it is reused.
- `RemoteLogin` clients get `ErrUnauthorized` and the session is cleared,
  unless the client was created with `WithPasswordRelogin`. Then goipa
  logs in again with the password it kept in process memory and retries;
  goroutines that hit the 401 together share one login. A password FreeIPA
  rejects is forgotten, so it is not tried again, and `ClearSession` forgets
  it too. This needs sticky sessions (the default).
- A client restored from a saved session ID has neither, so it gets
  `ErrUnauthorized`.

For a host that is not enrolled in FreeIPA, give the host, realm and CA:

```go
client, err := ipa.New(
	ipa.WithHost("ipa.example.com"),
	ipa.WithRealm("EXAMPLE.COM"),
	ipa.WithCACert(caPEM), // the contents of /etc/ipa/ca.crt
)
```

Add `WithKrb5Config(path)` or `WithKrb5ConfigData(text)` for Kerberos logins,
and `WithPasswordRelogin()` for the re-login above. With no options `New`
reads `/etc/ipa/default.conf` and `/etc/ipa/ca.crt`, but only when a client is
first created, not at import.

Full API reference: [pkg.go.dev/github.com/neverlless/goipa](https://pkg.go.dev/github.com/neverlless/goipa).

## Migrating from ubccr/goipa

The API is the same as ubccr/goipa v0.0.7. Change the import path:

```sh
grep -rl ubccr/goipa --include='*.go' . | xargs sed -i 's#ubccr/goipa#neverlless/goipa#'
go mod tidy
```

On macOS use `sed -i ''`. What changed since v0.0.7 is listed in the
[ChangeLog](CHANGELOG.md).

## Differences from upstream

- Security updates: `golang.org/x/crypto` and friends are current, and
  Dependabot and govulncheck keep them that way
- Bug fixes: `ErrUserExists` no longer has the same message as
  `ErrUnauthorized`; Kerberos and request-building errors are returned
  instead of being ignored
- `go test ./...` runs without a FreeIPA server; tests that need one are
  behind the `integration` build tag
- CI with race detector, staticcheck, gosec and govulncheck
- No logging: upstream's trace logs wrote passwords, random passwords and
  session cookies into the caller's log
- A `Client` is safe for concurrent use
- `include` and `includedir` in krb5.conf are resolved, so Kerberos logins
  work on ipa-client 4.13 hosts
- The `RPC` escape hatch, typed errors and `context.Context` support
- `ipatest`, a fake FreeIPA server, and contract tests that run the same
  checks nightly against real FreeIPA 4.9, 4.12 and 4.13

## Development

```sh
go test -race ./...
```

Consumers can test their own code without a FreeIPA server using the fake in
[`ipatest`](https://pkg.go.dev/github.com/neverlless/goipa/ipatest).

Integration tests run against a real FreeIPA in a container (Linux, Docker, sudo):

```sh
scripts/ipa-up.sh && (set -a; . ./.env; set +a; go test -race -tags integration -count=1 ./...) ; scripts/ipa-up.sh down
```

`ipa-up.sh` rewrites `/etc/krb5.conf` (backed up once to
`/etc/krb5.conf.goipa-bak`), `/etc/ipa/` and your ccache, and refuses to run
on a host whose `/etc/ipa/default.conf` points at another IPA server unless
`FORCE=1` is set.

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

goipa is released under a BSD-style license. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2015 Andrew E. Bruno and the goipa authors
([AUTHORS.rst](AUTHORS.rst)).
