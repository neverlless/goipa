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

## v0.2.1 — Kerberos login on FreeIPA 4.13 clients

Keytab, password and ccache logins fail on hosts enrolled with
ipa-client 4.13 (RHEL / CentOS Stream 9 and 10) unless the realm publishes
DNS SRV records: `failed to communicate with KDC ... lookup
_kerberos._tcp.<REALM> ... no such host`. ipa-client-install 4.13 writes
`[realms]` to `/etc/krb5.conf.d/freeipa-realm` and leaves only
`includedir /etc/krb5.conf.d/` and `dns_lookup_kdc = true` in
`/etc/krb5.conf`, and gokrb5 ignores `include`/`includedir`.

- [x] `Login`, `LoginWithKeytab` and `LoginFromCCache` resolve `include` and
      `includedir` in `DefaultKerbConf` the way MIT krb5 does: `includedir`
      reads only file names matching `[A-Za-z0-9_-]+` or `*.conf` (skips
      `.rpmsave`, editor backups), in sorted order; nesting is bounded. No
      API change; a krb5.conf without includes is parsed exactly as before
- [x] Value precedence matches MIT krb5 for settings defined both in
      krb5.conf and an included file (includes expanded in place): the
      first value wins for single values (`[libdefaults]` keys,
      `[domain_realm]`); a realm defined in several files is merged and
      all its `kdc` entries are used, krb5.conf's first. Verified against
      gokrb5's merge order and pinned with a test
- [x] Tests on the ipa-client 4.13.4 layout (`freeipa-realm`,
      `sssd_enable_idp`, a stale `.rpmsave`), a file without includes,
      nested `include`, a missing `includedir`, and an include loop

Accept: `LoginWithKeytab` finds the KDC from `/etc/krb5.conf.d/freeipa-realm`
with `dns_lookup_kdc = true` and no SRV records. Applications that worked
around it (mokey's container entrypoint appends the realm file to
krb5.conf) can drop the workaround.

## v0.3.0 — Test infrastructure

- [x] `ipatest`: exported fake FreeIPA server (`NewServer(t)`, seed helpers,
      `Client()`/`ClientAs(uid)`, call log, `Handle` for error injection),
      with documented FreeIPA quirks, each pinned by a test
- [x] Unit tests for the whole existing API against `ipatest`; coverage
      ≥ 80 % with Codecov
- [x] Nightly integration workflow against real FreeIPA containers
      (`almalinux-8-4.9.13`, `almalinux-9-4.12.2`, `almalinux-9-4.13.4`); the
      same contract tests run against `ipatest` and the real server
- [x] Replace the CentOS 7 `container/` setup with a `docker run` script
- [x] pkg.go.dev examples for the login modes and the `RPC` escape hatch

Accept: `go test ./...` coverage ≥ 80 %; the nightly job is green on all
three FreeIPA versions.

## v0.4.0 — Users and groups

- [x] Groups: `GroupShow`, `GroupFind`, `GroupAdd`, `GroupMod`, `GroupDelete`,
      `GroupAddMember`/`GroupRemoveMember` (users and groups),
      `GroupAddMemberManager`/`GroupRemoveMemberManager`; per-member failures
      surface as errors. Based on ubccr/goipa#9 by @earthquakesan, #14 by
      @ivanovilia96 and #17 by @m-vinc
- [x] User fields: all `mail` values as `Emails` (`Email` stays the first;
      ubccr/goipa#10), `IndirectGroups` (`memberofindirect_group`, as in
      fajo-de's fork), address (`street`, `l`, `st`, `postalcode`),
      `PreferredLanguage`, `Title`, `OrgUnit`, passkey mappings
- [x] `UserMod` no longer drops additional mail addresses
- [x] `SetPassword` omits an empty OTP; `randompassword` parsed in every form
      servers return (both found by tubby1981)
- [x] `HostShow`, `HostFind` (ubccr/goipa#11)

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
      time. Old constructors stay. `WithKrb5Config` takes a path (includes
      resolved as in v0.2.1) or a `*config.Config`, since `DefaultKerbConf`
      is a const and stays one
- [ ] Kerberos login from in-memory config, keytab or credential cache, for
      containers and secret stores (idea from sitnikovv's fork); `WhoAmI`
- [ ] Expired session: clear it and retry once through Kerberos when the
      client has credentials
- [ ] Opt-in re-login for password sessions: a client created with an
      explicit option keeps the `RemoteLogin` credentials and logs in again
      once when a call returns 401. Off by default, because it keeps the
      password in memory
- [ ] "Which login to use" table in the README and package doc: `RemoteLogin`
      (password over HTTPS, no Kerberos), `Login` (password through the
      KDC, needs krb5.conf), `LoginWithKeytab`, `LoginFromCCache`, and a
      saved session. Says plainly that `Login` is Kerberos and shows the
      CA setup for hosts not enrolled in FreeIPA

## v0.7.0 — Breadth without a generated API

Generated clients such as [go-freeipa](https://github.com/ccin2p3/go-freeipa)
type all of FreeIPA's ~460 commands as pointer-heavy argument structs. goipa
keeps a hand-written API for the common objects and makes every other
command just as safe to call. Code generation is used only for data (the
command catalogue), never for the public call API.

- [ ] Typed escape hatch: a generic `Call[T any](ctx, c, method, args,
      opts) (T, *Result, error)` that decodes `result` into the caller's
      struct, and an `Entry` type with `Str`, `Strs`, `Bool`, `Int`,
      `Time` and `DN` accessors that understand FreeIPA's attribute lists,
      `__datetime__` and `__base64__` values, so no caller parses gjson by hand
- [ ] Command catalogue generated from FreeIPA's `API.txt` for each supported
      release (4.9 to 4.13): command names, positional args, option names
      and types, and the release that introduced each. `RPC` and `Call` can
      validate a method and its options against it (opt-in), and
      `ipa.Commands` lets callers discover what a server version supports.
      `go generate` refreshes it; a CI job fails when a new FreeIPA release
      adds commands that the catalogue lacks
- [ ] Server version awareness: `ServerVersion` from the first response
      (the envelope carries it), and typed calls for features newer than
      the server (passkeys 4.11, sub-IDs 4.9.7, password-quality credits
      4.13) return `ErrNotSupported` instead of a confusing server error
- [ ] Attribute-level updates for any object: `Modify(ctx, c, command,
      pkey).Set(attr, v).Add(attr, v).Del(attr, v)` over FreeIPA's
      `setattr`/`addattr`/`delattr`, so a single field changes without the
      read-modify-write that `UserMod` needs today
- [ ] `batch` support: several commands in one round trip, with per-command
      results and errors
- [ ] Paging helpers for `*_find`: report `Truncated` as an error option or
      iterate with an explicit `sizelimit`, so large directories don't
      silently return 100 entries
- [ ] Typed APIs for the objects users ask for most, each with a `Context`
      twin, an `ipatest` model and contract tests on real FreeIPA, in this
      order: host groups; services and keytab metadata; HBAC and sudo rule
      management (create, members, enable/disable); certificates
      (`cert_request`, `cert_show`, `cert_revoke`); DNS zones and records;
      automember rules; roles, privileges and permissions (read)
- [ ] `ipatest` record/replay: record raw responses from a real server in
      the nightly run (`IPATEST_RECORD=dir`) and replay them for commands
      it doesn't model, so tests of unwrapped commands use real shapes
- [ ] Comparison table in the README (goipa vs generated clients) that says
      plainly when go-freeipa is the better fit

Accept: any FreeIPA command can be called with typed decoding and option
validation, without hand-written JSON parsing; the listed objects have
typed APIs verified nightly on FreeIPA 4.9, 4.12 and 4.13.

## v1.0.0 — Stable API

- [ ] API review: deprecations marked, error model and context policy final,
      `ipatest` API final
- [ ] Listed in [awesome-go](https://github.com/avelino/awesome-go) (Third-party APIs)
- [ ] Invite authors of active forks to contribute here

## Out of scope

- An LDAP backend, a CLI, non-FreeIPA identity systems.
- Generating the whole API from FreeIPA's schema. If you need every one of
  FreeIPA's ~460 commands as typed calls, use
  [go-freeipa](https://github.com/ccin2p3/go-freeipa); goipa's `RPC` covers
  the long tail.
