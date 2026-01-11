# proc-jail

Python bindings for [proc_jail](https://github.com/tenuo-ai/proc_jail) - process execution guard for agentic systems.

[![PyPI](https://img.shields.io/pypi/v/proc-jail.svg)](https://pypi.org/project/proc-jail/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

`proc-jail` provides a safe wrapper around process spawning, preventing command injection via argv-style execution with strict validation.

## Features

- **No shell interpretation**: Commands use argv-style execution, not shell strings
- **Absolute paths only**: Avoids PATH hijacking
- **Allowlist-only**: Explicit enumeration of permitted binaries and flags
- **Fail closed**: Any error or ambiguity results in denial
- **Type-safe API**: Type hints included
- **Resource limits**: Timeout, stdout/stderr byte limits
- **Double-dash injection**: Automatic `--` insertion to prevent flag injection

## Installation

```bash
pip install proc-jail
```

**Note**: Unix only (Linux, macOS). Windows is not supported.

## Quick Start

```python
from proc_jail import (
    ProcPolicyBuilder,
    ProcRequest,
    ArgRules,
    InjectDoubleDash,
)

# Build a policy
policy = (
    ProcPolicyBuilder()
    .allow_bin("/usr/bin/grep")
    .arg_rules(
        "/usr/bin/grep",
        ArgRules()
        .allowed_flags(["-n", "-i", "-l", "-c"])
        .max_flags(4)
        .max_positionals(10)
        .inject_double_dash(InjectDoubleDash.AfterFlags),
    )
    .timeout_secs(30)
    .build()
)

# Create and execute a request
request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
prepared = policy.prepare(request)
output = prepared.spawn_sync()

print(output.stdout_string())
```

## Why proc-jail?

Traditional process spawning is dangerous in agentic systems:

```python
# VULNERABLE: Shell injection
import subprocess
subprocess.run(f"grep '{query}' file.txt", shell=True)

# Attacker sets: query = "x'; rm -rf / #"
# Executes: grep 'x'; rm -rf / #' file.txt
```

With proc-jail, the same attack becomes harmless:

```python
from proc_jail import ProcPolicyBuilder, ProcRequest, ArgRules

policy = (
    ProcPolicyBuilder()
    .allow_bin("/usr/bin/grep")
    .arg_rules("/usr/bin/grep", ArgRules().max_positionals(2))
    .build()
)

request = ProcRequest("/usr/bin/grep", [query, "file.txt"])
output = policy.prepare(request).spawn_sync()

# If query = "x'; rm -rf / #"
# Executes: grep "x'; rm -rf / #" file.txt
# The injection is just a literal string, not interpreted
```

## API Reference

### ProcPolicyBuilder

Builder for process execution policies.

```python
policy = (
    ProcPolicyBuilder()
    .allow_bin("/usr/bin/grep")           # Add allowed binary
    .arg_rules("/usr/bin/grep", rules)    # Set argument rules
    .risky_bin_policy(RiskyBinPolicy.DenyByDefault)  # Handle risky binaries
    .env_locale_only()                    # Environment policy
    .cwd("/tmp")                          # Working directory
    .timeout_secs(30)                     # Timeout
    .max_stdout(10 * 1024 * 1024)         # Max stdout bytes
    .max_stderr(1 * 1024 * 1024)          # Max stderr bytes
    .build()
)
```

### ArgRules

Rules for validating arguments to a binary.

```python
rules = (
    ArgRules()
    .subcommand("status")                 # Pin subcommand (e.g., git status)
    .allowed_flags(["-n", "-i", "--color=never"])  # Allowed flags
    .max_flags(3)                         # Max flag count
    .max_positionals(10)                  # Max positional args
    .inject_double_dash(InjectDoubleDash.AfterFlags)  # Insert -- 
)
```

### ProcRequest

A proposed execution request.

```python
request = (
    ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
    .with_cwd("/var/log")
    .with_env({"LANG": "C"})
)
```

### Output

Result from command execution.

```python
output = prepared.spawn_sync()

output.success          # bool: Did process exit successfully?
output.exit_code        # int | None: Exit code
output.stdout           # bytes: Raw stdout
output.stderr           # bytes: Raw stderr
output.stdout_string()  # str: stdout as UTF-8 (lossy)
output.stderr_string()  # str: stderr as UTF-8 (lossy)
```

### Enums

```python
class RiskyBinPolicy:
    DenyByDefault = 0   # Deny shells/interpreters even if allowed
    AllowWithWarning = 1  # Allow with warning
    Disabled = 2        # No special handling

class InjectDoubleDash:
    Never = 0           # Never inject --
    AfterFlags = 1      # Inject -- between flags and positionals
```

## Environment Policies

```python
.env_empty()            # Pass no environment (default)
.env_locale_only()      # Pass LANG=C.UTF-8, LC_ALL=C.UTF-8
.env_fixed({"K": "V"})  # Pass specific variables
.env_allowlist(["PATH", "HOME"])  # Filter from request
```

Dangerous variables (`LD_PRELOAD`, `PYTHONPATH`, etc.) are always stripped.

## Platform Support

**Unix only** (Linux, macOS). Windows is not supported because `CreateProcess` passes arguments as a single string that each program parses differently, making injection prevention impossible to guarantee.

## Integration with Tenuo Ecosystem

| Crate | Threat | Boundary |
|-------|--------|----------|
| `path-jail` | Path traversal | Filesystem |
| `safe-unzip` | Zip Slip / bombs | Archive extraction |
| `url-jail` | SSRF | Network |
| `proc-jail` | Command injection | Process spawning |

## License

MIT OR Apache-2.0

