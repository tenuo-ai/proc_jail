# proc_jail

Process execution guard for agentic systems.

[![Crates.io](https://img.shields.io/crates/v/proc_jail.svg)](https://crates.io/crates/proc_jail)
[![PyPI](https://img.shields.io/pypi/v/proc_jail.svg)](https://pypi.org/project/proc_jail/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

`proc_jail` provides a safe wrapper around process spawning, enforcing deterministic bounds on process execution to prevent command injection, unauthorized binary execution, and resource abuse.

## Features

- **No shell interpretation**: Commands use argv-style execution, not shell strings
- **Allowlist-only**: Explicit enumeration of permitted binaries and flags
- **Fail closed**: Any error or ambiguity results in denial
- **Resource limits**: Timeout, stdout/stderr byte limits
- **Double-dash injection**: Automatic `--` insertion to prevent flag injection
- **Python and Rust APIs**: Native bindings for both languages

## Quick Start (Python)

```bash
pip install proc_jail
```

```python
from proc_jail import ProcPolicyBuilder, ProcRequest, ArgRules

# Define a policy
policy = (
    ProcPolicyBuilder()
    .allow_bin("/usr/bin/grep")
    .arg_rules("/usr/bin/grep", 
        ArgRules()
        .allowed_flags(["-n", "-i", "-l", "-c"])
        .max_flags(4)
        .max_positionals(10)
        .inject_double_dash())
    .timeout(30)
    .build()
)

# Create and execute a request
request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
output = policy.prepare(request).spawn_sync()

print(output.stdout_string())
```

## Quick Start (Rust)

```toml
[dependencies]
proc_jail = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use proc_jail::{ProcPolicy, ProcRequest, ArgRules, InjectDoubleDash};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules("/usr/bin/grep", ArgRules::new()
            .allowed_flags(&["-n", "-i", "-l", "-c"])
            .max_flags(4)
            .max_positionals(10)
            .inject_double_dash(InjectDoubleDash::AfterFlags))
        .timeout(Duration::from_secs(30))
        .build()?;

    let request = ProcRequest::new(
        "/usr/bin/grep",
        vec!["-n".into(), "pattern".into(), "file.txt".into()],
    );

    let output = policy.prepare(request)?.spawn().await?;
    println!("{}", output.stdout_string());
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

```python
request = ProcRequest("/usr/bin/grep", [query, "file.txt"])
output = policy.prepare(request).spawn_sync()

# If query = "x'; rm -rf / #"
# Executes: grep "x'; rm -rf / #" file.txt
# The injection is just a literal string, not interpreted
```

## Policies

### Binary Allowlist

Only explicitly allowed binaries can be executed:

```python
ProcPolicyBuilder()
    .allow_bin("/usr/bin/grep")
    .allow_bin("/usr/bin/jq")
    # ...
```

### Argument Rules

Every binary requires explicit argument rules:

```python
.arg_rules("/usr/bin/grep", 
    ArgRules()
    .allowed_flags(["-n", "-i", "-l"])
    .max_flags(3)
    .max_positionals(10)
    .inject_double_dash())
```

### Subcommand Pinning

Pin allowed subcommands for tools like git:

```python
.arg_rules("/usr/bin/git",
    ArgRules()
    .subcommand("status")
    .allowed_flags(["--porcelain", "-s"])
    .max_flags(2)
    .max_positionals(0))
```

### Risky Binary Detection

Shells, interpreters, and privilege escalation tools are blocked by default:

```python
# Even if allowed, bash is denied by default
policy.prepare(ProcRequest("/bin/bash", []))  # Error: BinRiskyDenied

# Opt-in with explicit acknowledgment
ProcPolicyBuilder()
    .allow_risky_binaries()
    # ...
```

### Environment Control

By default, no environment variables are passed. Dangerous variables (`LD_PRELOAD`, `PYTHONPATH`, etc.) are always stripped.

### Resource Limits

```python
ProcPolicyBuilder()
    .timeout(30)           # seconds
    .max_stdout(10485760)  # 10 MB
    .max_stderr(1048576)   # 1 MB
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

## Repository Structure

```
proc_jail/
├── src/           # Rust library source
├── tests/         # Rust integration tests
├── docs/          # Documentation
├── python/        # Python bindings (PyO3)
│   ├── src/       # Rust binding code
│   └── proc_jail/ # Python package
└── ...
```

## Development

```bash
# Build Rust library
cargo build

# Run tests
cargo test

# Build Python bindings
cd python
pip install maturin
maturin develop
```

## License

MIT OR Apache-2.0
