# Contributing to goipa

Thanks for helping! Bug reports, docs fixes and new FreeIPA commands are all
welcome. This project is the maintained continuation of
[ubccr/goipa](https://github.com/ubccr/goipa). For anything bigger than a
small fix, please open an issue first so we can agree on the API.

If you maintain a fork of ubccr/goipa or have local changes that are not
here, you are very welcome to contribute them: open an issue or a pull
request and we will work out the API together. Credits for earlier work are
in the [README](README.md#credits).

## Reporting issues

- Use the [issue forms](https://github.com/neverlless/goipa/issues/new/choose)
  for bugs and feature requests.
- For security vulnerabilities, **do not open a public issue**; see
  [SECURITY.md](SECURITY.md).
- Scrub passwords, keytabs, session cookies and principals from logs you paste.

## Development

Requirements: Go (version from `go.mod`). The default test suite needs no
FreeIPA server.

```sh
go test -race ./...
gofmt -l . && go vet ./... && go vet -tags integration ./...
```

CI also runs `govulncheck`, `staticcheck` and `gosec`, and fails when test
coverage drops below 80 % (see [.github/workflows/ci.yml](.github/workflows/ci.yml)
for the exact versions and flags).

Integration tests talk to a real FreeIPA and are behind the `integration`
build tag. On Linux with Docker:

```sh
scripts/ipa-up.sh && (set -a; . ./.env; set +a; go test -race -tags integration -count=1 ./...) ; scripts/ipa-up.sh down
```

`ipa-up.sh` rewrites `/etc/krb5.conf` (backed up once to
`/etc/krb5.conf.goipa-bak`), `/etc/ipa/` and your ccache, and refuses to run
on a host whose `/etc/ipa/default.conf` points at another IPA server unless
`FORCE=1` is set.

## Adding a FreeIPA command

- Check the command's arguments and result attributes against the server's
  own schema (`ipa -vv <command>`, or `json_metadata` over
  `/ipa/session/json`), not against memory. Attribute names differ between
  calls with and without `all: true`.
- Doc comment: name the FreeIPA command it wraps and the privilege it needs.
- Every new method `M` gets `MContext(ctx, same args)`, and `M` calls it with
  `context.Background()`. Add a row to `twinCalls` in `context_test.go`;
  `TestEveryMethodHasContextTwin` fails without one.
- Return a server error as the bare `*IpaError` (callers type-assert it),
  never modify the caller's `Options`, and don't log: the library has no
  logging.
- Add a unit test against `ipatest`; model the command in `ipatest` with a quirk
  test if FreeIPA behaves unusually. Add a contract test when the behaviour
  depends on the server.

## Contract tests

A contract test calls `forEachBackend`, which runs the same body against
`ipatest` and, with `-tags integration`, against a real FreeIPA. The nightly
[integration workflow](.github/workflows/integration.yml) runs them against
FreeIPA 4.9, 4.12 and 4.13; a maintainer can also start it by hand
(`workflow_dispatch`). Changes to FreeIPA behaviour need it green before
merge. Every `ipatest` behaviour that mirrors a FreeIPA quirk is a numbered
`Qn` entry in `ipatest/doc.go` naming the test that pins it.

## Refreshing recorded responses

`ipatest/replay/<version>/` holds responses recorded on real FreeIPA. To
refresh them, run the integration workflow (it records with `IPATEST_RECORD`
and uploads a `replay-<image>` artifact per FreeIPA version), then:

```sh
gh run download <run-id> -R neverlless/goipa -D /tmp/replay
```

Each `replay-<image>` folder of the download holds one `<version>/` folder
(e.g. `/tmp/replay/replay-almalinux-9-4.13.4/4.13.4/`); replace each
`ipatest/replay/<version>/` with the matching one, scan the
files for secrets (passwords, keys, tokens, real host names) the recorder's
redaction missed, run `go test ./ipatest/...`, and commit.

## Compatibility

goipa is used in production. Every exported identifier from
any released tag keeps its signature for all of v1; add new functions or fields
instead of changing existing ones. CI's "API compatibility" job (apidiff)
fails on incompatible changes against the latest tag. Breaking changes need
an issue first.

## Pull requests

- Keep changes focused: one logical change per PR.
- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:` ...).
- Add or update tests; keep CI green.
- Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` when behaviour or
  API changes.
- When your PR builds on someone else's work (an upstream PR or a fork),
  credit them in the commit message, e.g. `Based on ubccr/goipa#17 by @m-vinc`.

## License

By contributing you agree that your contributions will be licensed under the
BSD-style license in [LICENSE](LICENSE).
