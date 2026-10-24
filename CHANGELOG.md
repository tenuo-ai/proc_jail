# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `PreparedCommand::wrap_with()` to launch the validated command through another program (for example an OS sandbox launcher), plus `launch_program()`/`launch_args()` accessors
- `PreparedCommand::with_launch_env()` and `launch_env()` for environment variables added after the env policy
- Python bindings for `wrap_with`, `with_launch_env`, `launch_program`, `launch_args`

### Changed

- Commands are spawned in their own process group, and the whole group is killed on timeout or output limits
- An output limit on one stream no longer waits for the other stream to close
- Processes the command leaves running in its group are killed when it exits
- The timeout now also covers waiting for exit after the output pipes close

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
