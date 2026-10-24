Responses recorded from real FreeIPA servers by `ipatest.NewRecorder`, one
`<release>/<method>.json` per command: the envelope's `result`, with secrets
replaced by `REDACTED`. The integration workflow uploads them as the
`replay-<image>` artifacts; ipatest answers them for commands it does not
model (see `Server.SetReplay`).

The servers that recorded them use realm `EXAMPLE.TEST` and base
`dc=example,dc=test`; the modelled commands answer `TEST.LOCAL` and
`dc=test,dc=local`, so principals and DNs differ between the two.
