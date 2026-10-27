# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-10-27

### Fixed

- A command stopped by its timeout or an output limit now returns the output it wrote right before it was stopped. What was still unread in the pipes when it was killed is read too, within the limits and for at most 250 ms

## [0.3.0] - 2026-10-25

### Added

- `PartialOutput` and `ExecError::partial_output()`: a command stopped by its timeout or an output limit returns the output it wrote before it was stopped, capped at the limits
- Python `StoppedError`, a `RuntimeError` subclass whose `stdout` and `stderr` attributes expose the same bounded partial output

### Changed

- **Breaking:** `ExecError::Timeout`, `StdoutLimitExceeded` and `StderrLimitExceeded` have a new `partial` field. Patterns that list fields without `..` need updating

### Removed

- The obsolete, unmaintained `proc_jail_spec_v3.md`; the crate API, README, security policy, and maintained documentation are authoritative

## [0.2.0] - 2026-10-25

### Added

- `PreparedCommand::wrap_with()` to launch the validated command through another program (for example an OS sandbox launcher), plus `launch_program()`/`launch_args()` accessors
- `PreparedCommand::with_launch_env()` and `launch_env()` for environment variables added after the env policy
- Python bindings for `wrap_with`, `with_launch_env`, `launch_program`, `launch_args`

### Changed

- Commands are spawned in their own process group, and the whole group is killed on timeout or output limits
- An output limit on one stream no longer waits for the other stream to close
- Processes the command leaves running in its group are killed when it exits
- The timeout now also covers waiting for exit after the output pipes close
- Dropping the future returned by `spawn()` kills the command's process group

### Fixed

- `spawn_sync()` no longer deadlocks when called from a current-thread Tokio runtime
- Python releases now include `abi3` wheels for Linux and macOS on x86-64 and ARM64, plus a source distribution

### Security

- Upgraded PyO3 to 0.29.3 to address RUSTSEC-2026-0176 and RUSTSEC-2026-0177

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
