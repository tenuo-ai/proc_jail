# Design Decisions

This document explains the rationale behind key design decisions in proc_jail.

## No Shell Interpretation (R1)

**Decision**: proc_jail only accepts argv-style argument arrays. There is no API that accepts shell command strings.

**Rationale**: Shell interpretation is the root cause of command injection vulnerabilities. By eliminating it entirely, we remove an entire class of bugs. The Unix `execve` syscall receives an array of arguments with kernel-enforced boundaries. Shell metacharacters like `;`, `|`, `$()` are just literal characters.

**Trade-off**: Less convenient for quick scripts. Users must construct argument arrays explicitly.

## Absolute Paths Only (R2)

**Decision**: Binary paths must be absolute (start with `/`). No PATH lookup.

**Rationale**: PATH hijacking is a common attack vector. An attacker who can modify PATH or place a malicious binary earlier in PATH can intercept commands. Absolute paths eliminate this ambiguity.

**Trade-off**: Users must know where binaries are located. Different on different systems.

## Allowlist-Only Flags (R8)

**Decision**: There is no denylist API. Flags must be explicitly allowed.

**Rationale**: Denylists fail. Blocking `-f` does not block `--file`. Blocking `--file` does not block `--file=value`. Flag aliases vary across tools and versions. Allowlists are verbose but correct.

**Trade-off**: More upfront work to specify allowed flags.

## Mandatory ArgRules (R7)

**Decision**: Every allowed binary must have an `ArgRules` entry. There is no "allow any arguments" mode.

**Rationale**: "Allow binary with any args" defeats the purpose of proc_jail. Many binaries have dangerous flags (`-f`, `--exec`, etc.). If you want unrestricted execution, use `std::process::Command` directly.

**Trade-off**: Cannot quickly allow a binary without thinking about its arguments.

## Fail Closed (R13)

**Decision**: Any error, ambiguity, or validation failure results in denial.

**Rationale**: Security-critical code must fail safely. An unexpected edge case should block execution, not permit it. Users can explicitly allow edge cases if needed.

**Trade-off**: May block legitimate use cases that weren't anticipated.

## No Windows Support

**Decision**: proc_jail refuses to compile on Windows.

**Rationale**: Windows `CreateProcess` receives a single command-line string that each program parses differently. There is no kernel-enforced boundary between arguments. We cannot guarantee injection prevention. Providing a Windows build would give false confidence.

**Trade-off**: Cannot use proc_jail on Windows.

See [docs/windows.md](windows.md) for details.

## Double-Dash is Best-Effort (R9)

**Decision**: The `InjectDoubleDash` feature is opt-in and documented as best-effort.

**Rationale**: The POSIX `--` convention is widely but not universally followed. Some programs ignore it or parse it differently. We provide the feature for programs that do follow the convention but do not rely on it as the sole defense.

**Trade-off**: Users must test with their specific binaries.

## Risky Binary Detection is Advisory (R6)

**Decision**: The risky binary lists (shells, interpreters, etc.) are advisory. The default policy is to deny them even if allowlisted, but users can override.

**Rationale**: Defense in depth. Accidentally allowlisting `/bin/bash` is a common mistake. The risky binary check catches this. But the lists cannot be exhaustive, so users should not rely solely on them.

**Trade-off**: May block legitimate uses of interpreters.

## Environment Default is Empty (R10)

**Decision**: By default, no environment variables are passed to spawned processes.

**Rationale**: Environment variables can modify behavior in dangerous ways (LD_PRELOAD, PYTHONPATH, etc.). Starting from an empty environment and adding only what's needed is safer than starting from the parent's environment and trying to remove dangerous variables.

**Trade-off**: Programs that need environment variables require explicit configuration.

## Type-Safe API

**Decision**: Only `PreparedCommand` can spawn processes. `PreparedCommand` cannot be constructed outside of `ProcPolicy::prepare()`.

**Rationale**: Makes it impossible to accidentally bypass validation. The type system enforces the security invariant.

**Trade-off**: Slightly more verbose API.
