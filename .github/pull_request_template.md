## Summary

<!-- What does this change and why? Link the issue: Fixes #123 -->

## Testing

<!-- How did you verify it? Name the FreeIPA version for integration-tested changes. -->

## Checklist

- [ ] Tests added or updated, `go test -race ./...` passes
- [ ] `gofmt -l .` is empty and `go vet ./...` passes
- [ ] No change to the signature of an existing exported identifier
- [ ] New FreeIPA calls checked against the server schema, doc comment names the command and privilege
- [ ] New exported methods have a `…Context` twin
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if behavior or API changed
