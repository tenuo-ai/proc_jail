# proc_jail

Process execution guard for agentic systems.

[![Crates.io](https://img.shields.io/crates/v/proc_jail.svg)](https://crates.io/crates/proc_jail)
[![Documentation](https://docs.rs/proc_jail/badge.svg)](https://docs.rs/proc_jail)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

`proc_jail` provides a safe wrapper around process spawning, enforcing deterministic bounds on process execution to prevent command injection, unauthorized binary execution, and resource abuse.

## Features

- **No shell interpretation**: Commands use argv-style execution, not shell strings
- **Absolute paths only**: Avoids PATH hijacking
- **Allowlist-only**: Explicit enumeration of permitted binaries and flags
- **Fail closed**: Any error or ambiguity results in denial
- **Type-safe API**: Only validated commands can spawn processes
- **Resource limits**: Timeout, stdout/stderr byte limits
- **Double-dash injection**: Automatic `--` insertion to prevent flag injection

## Quick Start

```rust
use proc_jail::{ProcPolicy, ProcRequest, ArgRules, InjectDoubleDash};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define a policy
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules("/usr/bin/grep", ArgRules::new()
            .allowed_flags(&["-n", "-i", "-l", "-c"])
            .max_flags(4)
            .max_positionals(10)
            .inject_double_dash(InjectDoubleDash::AfterFlags))
        .timeout(Duration::from_secs(30))
        .build()?;

    // Create a request
    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-n".into(), "pattern".into(), "file.txt".into()],
    );

    // Validate and execute
    let prepared = policy.prepare(request)?;
    let output = prepared.spawn().await?;

    println!("stdout: {}", output.stdout_string());
    Ok(())
}
```

## Why proc_jail?

Traditional process spawning is dangerous in agentic systems:

```python
# VULNERABLE: Shell injection
subprocess.run(f"grep '{query}' file.txt", shell=True)

# Attacker sets: query = "x'; rm -rf / #"
# Executes: grep 'x'; rm -rf / #' file.txt
```

With proc_jail, the same attack becomes harmless:

```rust
let request = ProcRequest::new(
    "/usr/bin/grep",
    vec![query.clone(), "file.txt".into()],
);
let output = policy.prepare(request)?.spawn().await?;

// If query = "x'; rm -rf / #"
// Executes: grep "x'; rm -rf / #" file.txt
// The injection is just a literal string, not interpreted
```

## Policies

### Binary Allowlist

Only explicitly allowed binaries can be executed:

```rust
ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    .allow_bin("/usr/bin/jq")
    // ...
```

### Argument Rules

Every binary requires explicit argument rules:

```rust
.arg_rules("/usr/bin/grep", ArgRules::new()
    .allowed_flags(&["-n", "-i", "-l"])  // Allowlist-only
    .max_flags(3)
    .max_positionals(10)
    .inject_double_dash(InjectDoubleDash::AfterFlags))
```

### Subcommand Pinning

Pin allowed subcommands for tools like git:

```rust
.arg_rules("/usr/bin/git", ArgRules::new()
    .subcommand("status")  // Only "git status" allowed
    .allowed_flags(&["--porcelain", "-sb"])
    .max_flags(2)
    .max_positionals(0))
```

### Risky Binary Detection

Shells, interpreters, and privilege escalation tools are blocked by default:

```rust
// Even if allowed, bash is denied by default
policy.prepare(request_for("/bin/bash"));  // Error: BinRiskyDenied

// Opt-in with explicit acknowledgment
ProcPolicy::builder()
    .risky_bin_policy(RiskyBinPolicy::AllowWithWarning)
    // ...
```

### Environment Control

```rust
.env_policy(EnvPolicy::Empty)      // Default: no env
.env_policy(EnvPolicy::LocaleOnly) // LANG=C.UTF-8, LC_ALL=C.UTF-8
.env_policy(EnvPolicy::Fixed(map)) // Explicit values
```

Dangerous variables (`LD_PRELOAD`, `PYTHONPATH`, etc.) are always stripped.

### Resource Limits

```rust
.timeout(Duration::from_secs(30))
.max_stdout(10 * 1024 * 1024)  // 10 MB
.max_stderr(1 * 1024 * 1024)   // 1 MB
```

## Platform Support

**Unix only** (Linux, macOS). Windows is not supported because `CreateProcess` passes arguments as a single string that each program parses differently, making injection prevention impossible to guarantee. See [docs/windows.md](docs/windows.md) for details.

## Integration with Tenuo Ecosystem

| Crate | Threat | Boundary |
|-------|--------|----------|
| `path_jail` | Path traversal | Filesystem |
| `safe_unzip` | Zip Slip / bombs | Archive extraction |
| `url_jail` | SSRF | Network |
| `proc_jail` | Command injection | Process spawning |

## Documentation

- [SECURITY.md](SECURITY.md) - Security properties, limitations, threat model
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [docs/windows.md](docs/windows.md) - Why Windows is not supported
- [docs/risky-binaries.md](docs/risky-binaries.md) - Blocked binary categories
- [docs/design-decisions.md](docs/design-decisions.md) - Rationale for key decisions

## License

MIT OR Apache-2.0
