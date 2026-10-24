Responses recorded from real FreeIPA servers by `ipatest.NewRecorder`, one
`<release>/<method>.json` per command: the envelope's `result`, with secrets
replaced by `REDACTED`. The integration workflow uploads them as the
`replay-<image>` artifacts; ipatest answers them for commands it does not
model (see `Server.SetReplay`).
