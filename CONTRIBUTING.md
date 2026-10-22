# Contributing to goipa

Thanks for helping! Bug reports, docs fixes and new FreeIPA commands are all
welcome. This project is the maintained continuation of
[ubccr/goipa](https://github.com/ubccr/goipa). For anything bigger than a
small fix, please open an issue first so we can agree on the API.

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

CI also runs `govulncheck`, `staticcheck` and `gosec` (see
[.github/workflows/ci.yml](.github/workflows/ci.yml) for the exact versions
and flags).

Integration tests talk to a real FreeIPA and are behind the `integration`
build tag. A containerized server is provided:

```sh
cp .env.sample .env   # set passwords
docker compose up -d
ssh -p 9022 localhost
kinit admin && cd /app && go test -tags integration ./...
```

## Adding a FreeIPA command

- Check the command's arguments and result attributes against the server's
  own schema (`ipa -vv <command>`, or `json_metadata` over
  `/ipa/session/json`), not against memory. Attribute names differ between
  calls with and without `all: true`.
- Doc comment: name the FreeIPA command it wraps and the privilege it needs.
- Add a unit test; add an integration test when the behaviour depends on the
  server.

## Compatibility

goipa is on v0.x but is used in production. Exported identifiers from
ubccr/goipa v0.0.7 keep their signatures; add new functions or fields instead
of changing existing ones. Breaking changes need an issue first.

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
