# Roadmap

goipa is the maintained continuation of [ubccr/goipa](https://github.com/ubccr/goipa).
This roadmap is driven by demand: the open issues and pull requests upstream,
the features that forks of ubccr/goipa built on their own (nine forks added
group support, five added user attributes, four added hosts), and the raw
JSON-RPC calls that applications such as
[mokey](https://github.com/neverlless/mokey) send today because goipa lacks
them. Upstream items are referenced as `ubccr/goipa#NN`.

Rules that hold for every release:

- Every exported identifier of ubccr/goipa v0.0.7 keeps its signature until
  v1.0. New behaviour goes into new identifiers.
- FreeIPA command shapes are checked against FreeIPA's own `API.txt` and a
  live server, not memory. Support target: FreeIPA 4.9 (RHEL 8) to the latest
  4.13.
- Work harvested from forks and upstream pull requests credits its author.

Priorities may shift. Open an [issue](https://github.com/neverlless/goipa/issues)
to influence them.

## v0.1.0 — Maintained drop-in release

- [x] Module path `github.com/neverlless/goipa`; API identical to v0.0.7
- [x] `golang.org/x/crypto` 0.58.0 (GO-2026-5018; supersedes ubccr/goipa#18)
- [x] Stop logging requests and responses; drop logrus (trace logs leaked
      passwords, random passwords and session cookies)
- [x] `Client` safe for concurrent use; cookies other than `ipa_session` no
      longer fail an already-executed call
- [x] `ErrUserExists` message (from ubccr/goipa#14 by @ivanovilia96);
      unchecked request and SPNEGO errors
- [x] `go test ./...` runs without a server; CI with race detector,
      staticcheck, gosec, govulncheck; Dependabot
- [ ] Tag v0.1.0 (only this tag: upstream v0.0.x tags carry the old module path)
- [ ] Offer co-maintainership or upstreaming to ubccr/goipa in an issue

## v0.2.0 — Core: RPC, errors, context

The foundation every typed call builds on.

- [x] `Result` keeps the whole FreeIPA result: `Count`, `Truncated`,
      `Messages`, `Completed`, `Failed`, and `Raw` for shapes without a
      `result` key (e.g. `hbactest`)
- [x] Exported `(*Client).RPC` and `RPCContext`: any FreeIPA command with the
      client's TLS pool, session or Kerberos auth, and API version
      (ubccr/goipa#11 and every "raw call" workaround)
- [x] Typed errors: FreeIPA error code constants, `IpaError.Name`/`Data`,
      `errors.Is(err, ipa.ErrNotFound)` and friends; `*IpaError` itself stays
      unwrapped
- [x] HTTP 401 matches `ErrUnauthorized`; other non-200 responses return
      `*HTTPError`
- [x] Robustness: nil `result` is an error instead of a panic, response size
      cap, caller's `Options` map is not modified, `AddOTPToken` no longer
      writes into `DefaultTOTPToken` and sends token validity dates in UTC,
      replaced Kerberos clients are destroyed
- [x] `SetSessionID` to restore a saved session on any client
- [x] `…Context` twins of every existing method
- [x] CI: `apidiff` against the latest tag fails on incompatible changes

Accept: every v0.0.7 call site compiles unchanged; `RPC` works against a
server whose CA is only in the client's pool.

## v0.3.0 — Test infrastructure

- [ ] `ipatest`: exported fake FreeIPA server (`NewServer(t)`, seed helpers,
      `Client()`/`ClientAs(uid)`, call log, `Handle` for error injection),
      with documented FreeIPA quirks, each pinned by a test
- [ ] Unit tests for the whole existing API against `ipatest`; coverage
      ≥ 80 % with Codecov
- [ ] Nightly integration workflow against real FreeIPA containers
      (`almalinux-8-4.9.13`, `almalinux-9-4.12.2`, `almalinux-9-4.13.4`); the
      same contract tests run against `ipatest` and the real server
- [ ] Replace the CentOS 7 `container/` setup with a `docker run` script

Accept: `go test ./...` coverage ≥ 80 %; the nightly job is green on all
three FreeIPA versions.

## v0.4.0 — Users and groups

- [ ] Groups: `GroupShow`, `GroupFind`, `GroupAdd`, `GroupMod`, `GroupDelete`,
      `GroupAddMember`/`GroupRemoveMember` (users and groups),
      `GroupAddMemberManager`/`GroupRemoveMemberManager`; per-member failures
      surface as errors. Based on ubccr/goipa#9 by @earthquakesan, #14 by
      @ivanovilia96 and #17 by @m-vinc
- [ ] User fields: all `mail` values as `Emails` (`Email` stays the first;
      ubccr/goipa#10), `IndirectGroups` (`memberofindirect_group`, as in
      fajo-de's fork), address (`street`, `l`, `st`, `postalcode`),
      `PreferredLanguage`, `Title`, `OrgUnit`, passkey mappings
- [ ] `UserMod` no longer drops additional mail addresses
- [ ] `SetPassword` omits an empty OTP; `randompassword` parsed in every form
      servers return (both found by tubby1981)
- [ ] `HostShow`, `HostFind` (ubccr/goipa#11)

## v0.5.0 — Account lifecycle and access

- [ ] Stage users: add, show, find, mod, activate, delete
- [ ] Lockout: `UserStatus` (per-replica counters), `UserUnlock`,
      `PwPolicyShow` including the FreeIPA 4.13 password-quality credits
- [ ] Subordinate IDs: `SubIDFind`, `SubIDGenerate`
- [ ] HBAC and sudo: `HBACRuleFind`, `SudoRuleFind`, `HBACTest`
- [ ] Passkeys: `UserAddPasskey`, `UserRemovePasskey`
- [ ] OTP token sync (`/ipa/session/sync_token`; ubccr/goipa#2 by
      @farzandalaee)

Accept: an application can manage these without `RPC`; each call has a doc
comment naming the FreeIPA command and the privilege it needs, a unit test
against `ipatest` and an integration test.

## v0.6.0 — Construction and authentication

- [ ] `New(opts ...Option) (*Client, error)` with `WithHost`, `WithRealm`,
      `WithCACert`, `WithHTTPClient`, `WithKrb5Config`; no file I/O at import
      time. Old constructors stay
- [ ] Kerberos login from in-memory config, keytab or credential cache, for
      containers and secret stores (idea from sitnikovv's fork); `WhoAmI`
- [ ] Expired session: clear it and retry once through Kerberos when the
      client has credentials

## v1.0.0 — Stable API

- [ ] API review: deprecations marked, error model and context policy final,
      `ipatest` API final
- [ ] pkg.go.dev examples for every login mode and common task
- [ ] Listed in [awesome-go](https://github.com/avelino/awesome-go) (Third-party APIs)
- [ ] Invite authors of active forks to contribute here

## Out of scope

- An LDAP backend, a CLI, non-FreeIPA identity systems.
- Generating the whole API from FreeIPA's schema. If you need every one of
  FreeIPA's ~460 commands as typed calls, use
  [go-freeipa](https://github.com/ccin2p3/go-freeipa); goipa's `RPC` covers
  the long tail.
