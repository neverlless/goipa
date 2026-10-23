# goipa ChangeLog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (v0.x: minor releases may add API,
existing exported identifiers keep their signatures).

## [Unreleased]

- CI fails on any incompatible API change against the latest tag (apidiff).
- `(*Client).RPC` and `RPCContext` call any FreeIPA command with the client's
  TLS settings, session or Kerberos auth and API version (ubccr/goipa#11).
- `rpc` and `UserFind` no longer write `version`/`all`/`no_members` into the
  caller's `Options` map (data race when shared).
- `Result` keeps `Count`, `Truncated`, `Messages`, `Completed`, `Failed`, and
  the whole result object in `Raw` (for shapes without a `result` key such
  as `hbactest`).
- A response without `result` and `error` is an error instead of a
  nil-pointer panic.
- Responses over 64 MiB are rejected.
- FreeIPA error code constants (`CodeNotFound`, ...), `IpaError.Name` and
  `IpaError.Data`, and `errors.Is(err, ipa.ErrNotFound)` (also
  `ErrDuplicateEntry`, `ErrACI`, `ErrEmptyModlist`). Errors are still a bare
  `*IpaError`, so `err.(*ipa.IpaError)` keeps working.
- Non-200 JSON-RPC responses return `*HTTPError`; HTTP 401 (e.g. an expired
  session) matches `errors.Is(err, ipa.ErrUnauthorized)`. The message text is
  unchanged.
- `SetSessionID` restores a saved session on any client.
- Logging in again on the same `Client` destroys the previous Kerberos client
  instead of leaking its renewal goroutine and credentials.

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

[Unreleased]: https://github.com/neverlless/goipa/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/neverlless/goipa/compare/v0.0.7...v0.1.0
