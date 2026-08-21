## Summary

Describe the user-visible behavior and why it belongs in NestWG.

## Verification

- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] Privileged integration lab, when networking behavior changes
- [ ] Documentation updated

## Safety review

- [ ] Failure paths leave no bypass route or unmanaged resource
- [ ] Plans, logs, errors, and state contain no private or preshared keys
- [ ] Host routes and DNS remain unchanged unless explicitly documented
- [ ] New privileged inputs are strictly validated
