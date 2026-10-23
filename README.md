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
existing session, and gives you typed Go calls for users, passwords, SSH keys
and OTP tokens.

> **Note:** This is the maintained continuation of
> [ubccr/goipa](https://github.com/ubccr/goipa) by Andrew E. Bruno, which has
> had no release since 2024. It is a drop-in replacement for ubccr/goipa
> v0.0.7; see [Migrating from ubccr/goipa](#migrating-from-ubccrgoipa).
> It is developed alongside [mokey](https://github.com/neverlless/mokey), a FreeIPA self-service portal.

## Features

- Login: password (`Login`, `RemoteLogin`), keytab (`LoginWithKeytab`),
  Kerberos credential cache (`LoginFromCCache`), or a saved session ID
  (`NewDefaultClientWithSession`)
- Reads the host, realm and CA from `/etc/ipa/default.conf` and
  `/etc/ipa/ca.crt` on enrolled machines, or takes them explicitly
  (`NewClient`, `NewClientCustomHttp`)
- Users: show, find, add (with random or given password), modify, enable,
  disable, delete
- Passwords: set, change (with OTP), reset; typed errors for policy, invalid
  and expired passwords
- SSH public keys and user authentication types (password, OTP, ...)
- OTP tokens: add, list, enable, disable, remove

Groups, stage users, HBAC/sudo, sub-IDs, passkeys, password policy and a
generic `RPC` call are planned; see the [roadmap](ROADMAP.md).

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

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

goipa is released under a BSD-style license. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2015 Andrew E. Bruno and the goipa authors
([AUTHORS.rst](AUTHORS.rst)).
