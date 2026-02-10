# Contributing to ClawShield

Thanks for your interest in making AI agent infrastructure more secure! 🛡️

## How to Contribute

### Reporting Bugs

Open an issue using the [bug report template](https://github.com/lennystepn-hue/clawshield/issues/new?template=bug_report.md).

### Suggesting Features

Open an issue using the [feature request template](https://github.com/lennystepn-hue/clawshield/issues/new?template=feature_request.md).

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test: `go build ./... && go vet ./...`
5. Commit with a clear message
6. Push and open a Pull Request

### Adding Security Checks

New scanner checks go in `internal/scanner/scanner.go`. Each check returns a `CheckResult` with:
- **Name** — Short descriptive name
- **Category** — `Network`, `Access`, `System`, `Files`, `Agent`, or `Process`
- **Status** — `pass`, `warn`, `fail`, or `info`
- **Detail** — What was found
- **Fix** — How to fix it (for warn/fail)

### Adding Skill Scan Patterns

New detection patterns go in `internal/skills/scanner.go` in the `dangerousPatterns` slice. Include:
- A regex pattern
- Severity level (`critical`, `high`, `medium`, `low`)
- Human-readable description

## Code Style

- Standard Go formatting (`gofmt`)
- Keep it simple — this tool runs on production servers
- No external dependencies (stdlib only)

## Security Vulnerabilities

Please report security issues privately — see [SECURITY.md](SECURITY.md).
