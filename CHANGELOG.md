# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-11

### Added

- Initial release
- `ProcPolicy` builder for defining execution policies
- `ProcRequest` for specifying execution requests
- `PreparedCommand` typestate pattern ensuring validation before execution
- Binary allowlist with path canonicalization
- `ArgRules` for per-binary argument validation:
  - Flag allowlist (exact match)
  - `max_flags` and `max_positionals` limits
  - Subcommand pinning
  - Double-dash injection (`InjectDoubleDash::AfterFlags`)
- `RiskyBinPolicy` for blocking shells, interpreters, spawners, privilege tools
- `EnvPolicy` for environment control:
  - `Empty` (default)
  - `LocaleOnly`
  - `Fixed`
  - `AllowList`
- `ALWAYS_STRIP` list of dangerous environment variables
- `CwdPolicy` for working directory control:
  - `Fixed`
  - `Jailed`
  - `AllowList`
- `ResourceLimits` with timeout and output byte limits
- Comprehensive error types (`Violation`, `ExecError`)
- Async execution via `spawn()` and sync via `spawn_sync()`
- Unix-only support (compile-time Windows rejection)

### Security

- All shell metacharacters treated as literals (no shell interpretation)
- Symlink resolution before allowlist comparison
- Regular file and executable permission checks
- Defense against PATH hijacking (absolute paths required)
- Environment variable stripping (LD_PRELOAD, PYTHONPATH, etc.)

### Documentation

- README with quick start guide
- SECURITY.md with threat model and limitations
- docs/windows.md explaining Windows non-support
- docs/risky-binaries.md with category lists
- docs/design-decisions.md with rationale

### Testing

- 62 unit tests
- 12 integration tests with real binaries
- 24 adversarial tests covering:
  - Null byte injection
  - Unicode attacks (homoglyphs, RTL override)
  - Shell metacharacters
  - Path traversal
  - Flag injection
  - Environment bypass
  - Resource exhaustion boundaries
  - CWD escapes

