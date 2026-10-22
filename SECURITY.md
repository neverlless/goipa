# Security Policy

goipa authenticates to FreeIPA with passwords, keytabs and session cookies
and is used by identity-management tools, so security reports are taken
seriously.

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/neverlless/goipa/security/advisories/new)
("Report a vulnerability" on the Security tab) instead.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- Affected goipa version and FreeIPA version

You will get an answer within 7 days. A fix and advisory are published within
90 days, or sooner once a fix is available.

## Using goipa safely

- Log in with the least-privileged FreeIPA account that can run the commands
  you need, not `admin`. Keep keytabs readable by the service user only.
- goipa verifies the server certificate against the system roots plus
  `/etc/ipa/ca.crt`. Do not pass an `http.Client` with
  `InsecureSkipVerify` to `NewClientCustomHttp` outside tests.
- At logrus `trace` level goipa dumps full HTTP requests and responses,
  including passwords and session cookies. Never enable trace logging in
  production.
