# goipa

**Go client library for the FreeIPA / Red Hat IdM JSON-RPC API.**

[![CI](https://github.com/neverlless/goipa/actions/workflows/ci.yml/badge.svg)](https://github.com/neverlless/goipa/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/neverlless/goipa/branch/main/graph/badge.svg)](https://codecov.io/gh/neverlless/goipa)
[![Go Reference](https://pkg.go.dev/badge/github.com/neverlless/goipa.svg)](https://pkg.go.dev/github.com/neverlless/goipa)
[![Release](https://img.shields.io/github/v/release/neverlless/goipa)](https://github.com/neverlless/goipa/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/neverlless/goipa)](https://goreportcard.com/report/github.com/neverlless/goipa)
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
  (`SetSessionID`); see [Which login to use](#which-login-to-use)
- Kerberos clients recover expired sessions; password re-login is opt-in
  (`WithPasswordRelogin`); `WhoAmI`
- Reads the host, realm and CA from `/etc/ipa/default.conf` and
  `/etc/ipa/ca.crt` on enrolled machines, or takes them explicitly
  (`New` with `With*` options)
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
- Host groups, services and keytab access, HBAC and sudo rules, certificates,
  DNS, automember rules, roles, privileges and permissions: see
  [Typed objects](#typed-objects)
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
- `FindEntries` returns `ErrTruncated` when the server cut a search short;
  the typed Finds do so only with `WithTruncationErrors()`
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

## Typed objects

Each object has typed `…Show`/`…Find` calls (and `…Add`, `…Delete` and member
calls where noted), checked nightly against FreeIPA 4.9, 4.12 and 4.13. Member
calls return the updated object and a `*MemberError` for members the server
refused. Attributes are changed with `Modify` (`HostGroupAdd` and friends only
create); for automember use `RPC`, since `automember_mod` needs the rule type.
Finds that hit the server's size limit return what they got without an
error; create the client with `WithTruncationErrors()` to get `ErrTruncated`
with those entries instead.

| Object | Methods | FreeIPA commands |
|---|---|---|
| Host | `HostAdd`, `HostAddWithPassword`, `HostMod`, `HostDelete`, `HostDisable` (with `HostShow`/`HostFind`) | `host_add`, `_mod`, `_del` (`updatedns`), `_disable`, `_show`, `_find` |
| Stage user | `StageUserAdd`, `StageUserAddWithPassword`, `StageUserActivate` (with `StageUserShow`/`StageUserFind`) | `stageuser_add` (with `userpassword`), `_activate`, `_show`, `_find` |
| Host group | `HostGroupShow`, `HostGroupFind`, `HostGroupAdd`, `HostGroupDelete`, `HostGroupAddMember`, `HostGroupRemoveMember`, `HostGroupAddMemberManager`, `HostGroupRemoveMemberManager` | `hostgroup_show`, `_find`, `_add`, `_del`, `_add_member`, `_remove_member`, `_add_member_manager`, `_remove_member_manager` |
| Service | `ServiceShow`, `ServiceFind`, `ServiceAdd`, `ServiceDelete`, `ServiceDisable`, `ServiceAddHost`, `ServiceRemoveHost`, `ServiceAllow…Keytab`, `ServiceDisallow…Keytab` (retrieve, create) | `service_show`, `_find`, `_add`, `_del`, `_disable`, `_add_host`, `_remove_host`, `_allow_retrieve_keytab`, `_disallow_retrieve_keytab`, `_allow_create_keytab`, `_disallow_create_keytab` |
| HBAC rule | `HBACRuleShow`, `HBACRuleFind`, `HBACRuleAdd`, `HBACRuleDelete`, `HBACRuleEnable`, `HBACRuleDisable`, `HBACRuleAdd/RemoveUser`, `…Host`, `…Service` | `hbacrule_show`, `_find`, `_add`, `_del`, `_enable`, `_disable`, `_add_user`, `_remove_user`, `_add_host`, `_remove_host`, `_add_service`, `_remove_service` |
| Sudo rule | `SudoRuleShow`, `SudoRuleFind`, `SudoRuleAdd`, `SudoRuleDelete`, `SudoRuleEnable`, `SudoRuleDisable`, `SudoRuleAdd/RemoveUser`, `…Host`, `…AllowCommand`, `…DenyCommand`, `…RunAsUser`, `…RunAsGroup`, `…Option` | `sudorule_show`, `_find`, `_add`, `_del`, `_enable`, `_disable`, `_add_user`, `_add_host`, `_add_allow_command`, `_add_deny_command`, `_add_runasuser`, `_add_runasgroup`, `_add_option` and their `_remove_` twins |
| Certificate | `CertRequest`, `CertShow`, `CertRevoke` | `cert_request`, `cert_show`, `cert_revoke` |
| DNS zone | `DNSZoneShow`, `DNSZoneFind`, `DNSZoneAdd`, `DNSZoneDelete`, `DNSZoneEnable`, `DNSZoneDisable` | `dnszone_show`, `_find`, `_add`, `_del`, `_enable`, `_disable` |
| DNS record | `DNSRecordShow`, `DNSRecordFind`, `DNSRecordAdd`, `DNSRecordRemove`, `DNSRecordDelete` | `dnsrecord_show`, `_find`, `_add`, `_del` (remove values; `del_all` for the name) |
| Automember rule | `AutomemberShow`, `AutomemberFind`, `AutomemberAdd`, `AutomemberDelete`, `AutomemberAddCondition`, `AutomemberRemoveCondition`, `AutomemberDefaultGroup`, `AutomemberSetDefaultGroup`, `AutomemberRemoveDefaultGroup`, `AutomemberRebuild` | `automember_show`, `_find`, `_add`, `_del`, `_add_condition`, `_remove_condition`, `automember_default_group_show`, `_set`, `_remove`, `automember_rebuild` |
| Role, privilege, permission (read only) | `RoleShow`/`RoleFind`, `PrivilegeShow`/`PrivilegeFind`, `PermissionShow`/`PermissionFind` | `role_*`, `privilege_*`, `permission_*` `_show` and `_find` |

## Stability

goipa follows [Semantic Versioning](https://semver.org/). From v1.0.0:

- **API.** No exported identifier of `ipa` or `ipatest` is removed or changes
  signature within v1. This covers every identifier inherited from
  ubccr/goipa v0.0.7. Identifiers that newer ones supersede are marked
  `Deprecated` and stay. A breaking change would ship as
  `github.com/neverlless/goipa/v2`.
- **Errors.** FreeIPA errors stay bare `*IpaError` values, and sentinels and
  error types stay matchable with `errors.Is` and `errors.As` as documented
  under Errors. Error message text is not part of the API.
- **Wire behaviour.** A call sends the same command, arguments and options
  for the whole of v1, unless that shape is a bug against FreeIPA. Bugs are
  fixed in patch releases and listed in the [ChangeLog](CHANGELOG.md).
- **FreeIPA.** Supported: FreeIPA 4.9 (RHEL 8) to the latest 4.13 release,
  checked nightly against 4.9.13, 4.12.2 and 4.13.4; 4.10 and 4.11 are not
  tested. A newer FreeIPA release is added in a minor release. Dropping a
  FreeIPA line takes a minor release and a ChangeLog note one release ahead.
  Calls for features newer than the server fail with `ErrNotSupported`
  instead of reaching it.
- **Go.** goipa supports the two most recent Go releases, as the Go team
  does. Go 1.26 (the go.mod minimum) and the newest stable release are tested in
  CI. The `go` directive in go.mod moves only in a minor release, never in a
  patch.
- **ipatest.** Its API is stable as above. Its behaviour follows real FreeIPA
  and may change in minor releases (see the package documentation).
- **Command catalogue.** `Commands`/`LookupCommand` data grows with new
  FreeIPA releases. The maintainer does not remove entries, except the few
  listed in `allowedRemovals` in `internal/gencatalogue`.

Security note: on FreeIPA (seen on 4.9.13, 4.12.2 and 4.13.4) the server keeps accepting a session
cookie after `session_logout`, so logging out only makes the client forget it.
Treat a session ID as a credential until it expires.

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
	client, err := ipa.New()
	if err != nil {
		log.Fatal(err)
	}

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

`NewDefaultClient`, `NewClient` and `NewClientCustomHttp` still work but are
deprecated in favour of `New`.

Elsewhere, name the server and realm and log in with a password:

```go
client, err := ipa.New(ipa.WithHost("ipa.example.com"), ipa.WithRealm("EXAMPLE.COM"))
if err != nil {
	log.Fatal(err)
}
if err := client.RemoteLogin("jdoe", password); err != nil {
	switch {
	case errors.Is(err, ipa.ErrExpiredPassword):
		// ask for a new password, then client.SetPassword(...)
	case errors.Is(err, ipa.ErrInvalidPassword):
		// wrong password
	}
}
// Keep client.SessionID() and restore it later: ipa.New(...) then SetSessionID.
```

## Which login to use

| Method | How it authenticates | Needs | Use when |
|---|---|---|---|
| `RemoteLogin` | password over HTTPS (`/ipa/session/login_password`) | the CA; no Kerberos | web apps, scripts, hosts not enrolled |
| `Login` | password through the KDC (Kerberos) | krb5.conf (`WithKrb5Config*`), realm | you have a password and want a ticket |
| `LoginWithKeytab` / `LoginWithKeytabData` | keytab | krb5.conf, realm | services, daemons |
| `LoginFromCCache` / `LoginFromCCacheData` | an existing ticket cache (kinit) | krb5.conf | CLI tools run by a logged-in user |
| saved session (`SetSessionID`) | the `ipa_session` cookie | none | restoring a web session |

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

Kerberos clients send the first call to `/ipa/json` with SPNEGO; FreeIPA
answers with an `ipa_session` cookie and later calls use `/ipa/session/json`
with it, negotiating again only after a 401. The KDC therefore sees one ticket
request per session, not one per call. `LoginFromCCache` reads file caches
only (`FILE:` or a path). RHEL and Fedora default to `KCM:`, so run
`kinit -c /tmp/krb5cc_app` (or set `KRB5CCNAME=FILE:…`) or use a keytab.

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

## Credits

goipa builds on [ubccr/goipa](https://github.com/ubccr/goipa) by Andrew E.
Bruno, and on work from its pull requests and forks: [@earthquakesan](https://github.com/earthquakesan),
[@ivanovilia96](https://github.com/ivanovilia96),
[@m-vinc](https://github.com/m-vinc),
[@farzandalaee](https://github.com/farzandalaee),
[@Demacr](https://github.com/Demacr) (`UsersFindBy`, now `UserFind`),
[@tubby1981](https://github.com/tubby1981),
[@fajo-de](https://github.com/fajo-de) and
[@sitnikovv](https://github.com/sitnikovv). Thank you. If you maintain a
fork with changes that are not here, you are welcome to send them: open an
issue or a pull request (see [CONTRIBUTING.md](CONTRIBUTING.md)).

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

### Recorded responses

`ipatest` models the commands above and answers any other `*_show` or
`*_find` command from responses recorded on real FreeIPA 4.9.13, 4.12.2 and
4.13.4 (secrets redacted), so tests of commands goipa does not wrap see real
shapes. Order: a `Handle` override, then a built-in, then a recording, then
905. `Server.SetReplay(nil)` turns recordings off and `SetReplay(fsys)` uses
your own, written by `ipatest.NewRecorder`. The recordings are about 3 MB,
embedded in `ipatest` only.

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

goipa is released under a BSD-style license. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2015 Andrew E. Bruno and the goipa authors
([AUTHORS.rst](AUTHORS.rst)).
