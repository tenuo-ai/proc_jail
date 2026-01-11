# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-11

### Added

- Initial release
- Core `ProcPolicy` with builder pattern
- `ArgRules` for argument validation
  - Flag allowlist
  - Subcommand pinning
  - Double-dash injection
- `EnvPolicy` with ALWAYS_STRIP protection
- `CwdPolicy` for working directory control
- `ResourceLimits` (timeout, stdout/stderr caps)
- `RiskyBinPolicy` for shells, interpreters, spawners, privilege tools
- Path canonicalization with symlink resolution
- Python bindings via PyO3

### Security

- No shell interpretation (execve-style only)
- Absolute paths required
- Fail-closed design
- Environment variable sanitization
