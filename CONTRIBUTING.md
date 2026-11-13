# Contributing

Thanks for considering a contribution. The project is young, so please open
an issue to discuss anything larger than a small fix before writing code.

## Ground rules

- **No Nmap code or data.** Do not copy from Nmap or its fingerprint and
  service files. Their license is incompatible with this project's.
- **Standard library first.** A new dependency needs a reason in the pull
  request description.
- **Safe by default.** Changes must not weaken the scope checks, rate limits
  or audit behaviour without discussion.
- **Tests required.** Tests must not send traffic off the local machine.

## Before opening a pull request

```sh
gofmt -l .            # must print nothing
go vet ./...
go test -race ./...
golangci-lint run ./...
```

By contributing you agree that your work is licensed under Apache-2.0.
