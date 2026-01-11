# proc_jail v0.1 Specification

Process execution guard for agentic systems.

## Overview

`proc_jail` is a Rust library that provides a safe wrapper around process spawning. It enforces deterministic bounds on process execution to prevent command injection, unauthorized binary execution, and resource abuse.

## Platform Support

```rust
// lib.rs
#[cfg(windows)]
compile_error!(
    "proc_jail does not support Windows. \
     Windows CreateProcess passes arguments as a string that the child parses, \
     making injection prevention impossible to guarantee. \
     See docs/windows.md for details."
);
```

**Rationale:** On Unix, `execve` receives an argv array—the kernel enforces boundaries. On Windows, `CreateProcess` receives a single command-line string that each program parses differently. This is "psychology" (guessing how the child interprets the string), not "physics" (kernel-enforced boundaries). proc_jail promises physics.

## Positioning

| Crate | Threat | Boundary |
|-------|--------|----------|
| `path_jail` | Path traversal | Filesystem |
| `safe_unzip` | Zip Slip / bombs | Archive extraction |
| `url_jail` | SSRF | Network |
| `proc_jail` | Command injection | Process spawning |

## Threat Model

### Attacker Capabilities

- Can influence the command to be executed (directly or via prompt injection)
- Knows tool schemas and error feedback
- Can attempt multiple adaptive tries
- May control argument values passed to allowed binaries

### Defender Assumptions

- `proc_jail` is called before any process is spawned
- The host OS is not compromised
- Attacker does NOT have local filesystem write access (see TOCTOU note)
- Allowed binaries are trusted to execute as specified (but may have bugs)

### Out of Scope

- Syscall sandboxing (use seccomp/containers)
- Authorization and identity (use Tenuo)
- Side channels (timing)
- RCE vulnerabilities in allowed binaries
- Privilege escalation via OS vulnerabilities
- Natural language intent interpretation
- Local attackers with filesystem write access (TOCTOU)

## Non-Goals

`proc_jail` does not:

- Sandbox syscalls (use seccomp/containers for that)
- Provide authorization/identity/delegation (that's Tenuo)
- Interpret natural-language intent
- Guarantee a permitted binary is "safe" for all inputs
- Protect against kernel exploits
- Prevent allowed binaries from spawning subprocesses
- Defend against local privilege escalation

---

## Core Abstractions

### ProcPolicy

A deterministic policy describing what may be executed.

```rust
pub struct ProcPolicy {
    /// Allowed binaries (absolute paths, will be canonicalized)
    allowed_bins: HashSet<AbsolutePath>,
    
    /// Per-binary argument rules (REQUIRED for each allowed binary)
    arg_rules: HashMap<AbsolutePath, ArgRules>,
    
    /// How to handle risky binaries (interpreters, spawners)
    risky_bin_policy: RiskyBinPolicy,
    
    /// Environment variable policy
    env_policy: EnvPolicy,
    
    /// Working directory policy
    cwd_policy: CwdPolicy,
    
    /// Resource limits
    limits: ResourceLimits,
}
```

### ProcRequest

A proposed execution request.

```rust
pub struct ProcRequest {
    /// Absolute path to binary
    pub bin: AbsolutePath,
    
    /// Arguments (not including binary path)
    pub argv: Vec<String>,
    
    /// Environment variables (default: empty)
    pub env: HashMap<String, String>,
    
    /// Working directory (default: policy-defined)
    pub cwd: Option<AbsolutePath>,
}
```

### PreparedCommand

A validated command ready for execution. **Only this type can spawn processes.**

```rust
pub struct PreparedCommand {
    // Private fields - cannot be constructed outside proc_jail
    bin: AbsolutePath,
    argv: Vec<String>,
    env: HashMap<String, String>,
    cwd: AbsolutePath,
    limits: ResourceLimits,
}

impl PreparedCommand {
    /// Execute the prepared command
    pub async fn spawn(self) -> Result<Output, ExecError>;
    
    /// Execute synchronously
    pub fn spawn_sync(self) -> Result<Output, ExecError>;
}
```

### Type-Safe API

```rust
impl ProcPolicy {
    /// Validate a request and return a PreparedCommand
    /// This is the ONLY way to create a PreparedCommand
    pub fn prepare(&self, request: ProcRequest) -> Result<PreparedCommand, Violation>;
}

// Usage - type system enforces validation
let prepared = policy.prepare(request)?;  // Validates
let output = prepared.spawn().await?;     // Executes

// Impossible to spawn without validation - PreparedCommand has no public constructor
```

---

## Argument Parsing Model

proc_jail uses a simplified POSIX-style argument model.

### Definitions

| Term | Definition | Examples |
|------|------------|----------|
| **Flag** | Argument starting with `-` or `--` | `-f`, `-v`, `--verbose`, `--file=foo` |
| **Positional** | Argument not starting with `-`, OR any argument after `--` | `file.txt`, `pattern` |
| **Subcommand** | First positional argument when `ArgRules.subcommand` is set | `status` in `git status` |

### Special Cases

| Input | Classification | Rationale |
|-------|----------------|-----------|
| `-` | Positional | Convention for stdin |
| `--` | Terminator | Everything after is positional |
| `-abc` | Single flag `-abc` | NOT expanded to `-a -b -c` |
| `--file=foo` | Single flag `--file=foo` | NOT split into `--file` and `foo` |

### Allowlist Matching

Flags are matched **exactly** as provided in `allowed_flags`:

```rust
allowed_flags: hashset!["-f", "--file", "--color=always"]

"-f"             // ✅ Exact match
"--file"         // ✅ Exact match
"--color=always" // ✅ Exact match
"--file=foo"     // ❌ No match (would need "--file=" prefix pattern)
"-abc"           // ❌ No match (not expanded)
```

For flags that accept values, add the flag with `=` or handle in v0.2 with patterns.

---

## Normative Requirements

### R1 — No Shell Interpretation

**MUST NOT** execute via shell interpretation.

- No `sh -c`, `bash -c`, `cmd.exe /c`
- No pipeline strings (`"a | b"`) accepted as a single command
- API **MUST** require an argv vector (execve-style)

```rust
// ✅ Correct - argv style
policy.prepare(ProcRequest {
    bin: "/usr/bin/grep".into(),
    argv: vec![query, "file.txt".into()],
    ..Default::default()
})?;

// ❌ Impossible - no shell string API exists
policy.run_shell("grep '{}' file.txt", query);  // This API doesn't exist
```

**Rationale:** Eliminates shell metacharacter injection entirely.

### R2 — Absolute Binary Paths Only

The executable **MUST** be an absolute path.

```rust
"/usr/bin/git"  // ✅ Allowed
"git"           // ❌ Rejected (E_BIN_NOT_ABSOLUTE)
"./bin/git"     // ❌ Rejected (E_BIN_NOT_ABSOLUTE)
```

**Rationale:** Avoids PATH hijacking and ambiguity.

### R3 — Path Canonicalization

Binary paths **MUST** be canonicalized before comparison.

**Canonicalization rules:**

1. Request binary path **MUST** be absolute
2. Canonicalize request binary path (equivalent to `realpath`)
3. Canonicalize each allowlist entry at policy build time
4. Compare canonicalized paths (exact string match)
5. **MUST** deny if canonicalization fails (broken symlink, file doesn't exist, permission denied)

```rust
// Allowlist contains: /usr/bin/git

// ✅ Direct path
request.bin = "/usr/bin/git"  // Canonicalizes to /usr/bin/git, matches

// ✅ Symlink that resolves to allowed binary
// /usr/local/bin/git -> /usr/bin/git
request.bin = "/usr/local/bin/git"  // Canonicalizes to /usr/bin/git, matches

// ❌ Symlink to disallowed binary
// /tmp/safe -> /bin/bash
request.bin = "/tmp/safe"  // Canonicalizes to /bin/bash, not in allowlist

// ❌ Broken symlink
// /tmp/broken -> /nonexistent
request.bin = "/tmp/broken"  // Canonicalization fails, denied
```

**TOCTOU Note:** There is a race condition between canonicalization (`prepare()`) and execution (`spawn()`). See Security Notes.

**Rationale:** Prevents symlink-based bypass attacks.

### R4 — Binary Must Be Regular Executable File

After canonicalization, the binary path **MUST**:

1. Point to a regular file (`stat().is_file() == true`)
2. Be executable by the current user

**MUST** deny if:

- Path is a directory → `E_BIN_IS_DIRECTORY`
- Path is a device file, socket, FIFO, or other special file → `E_BIN_NOT_REGULAR_FILE`
- Path is not executable → `E_BIN_NOT_EXECUTABLE`

```rust
// ❌ Directory
request.bin = "/usr/bin"  // E_BIN_IS_DIRECTORY

// ❌ Device file
request.bin = "/dev/null"  // E_BIN_NOT_REGULAR_FILE

// ❌ Not executable
request.bin = "/etc/passwd"  // E_BIN_NOT_EXECUTABLE
```

**Rationale:** Prevents execution of non-binary paths.

### R5 — Binary Allowlist

The canonicalized executable path **MUST** match an allowlisted entry.

```rust
let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    .allow_bin("/usr/bin/git")
    .build()?;

// ✅ Allowed
policy.prepare(request_for("/usr/bin/grep"))?;

// ❌ Rejected (E_BIN_NOT_ALLOWED)
policy.prepare(request_for("/bin/rm"))?;
```

**Rationale:** Prevents execution of unexpected binaries.

### R6 — Risky Binary Policy

Certain binaries are high-risk (interpreters, command spawners). Policy **MUST** handle them explicitly.

```rust
pub enum RiskyBinPolicy {
    /// Deny risky binaries even if in allowlist (default)
    DenyByDefault,
    
    /// Allow risky binaries if explicitly in allowlist, log warning
    AllowWithWarning,
    
    /// No special handling (you're on your own)
    Disabled,
}
```

**Risky binary categories:**

| Category | Examples | Risk |
|----------|----------|------|
| Shell | sh, bash, zsh, dash | Arbitrary command execution |
| Interpreter | python, perl, ruby, node | Arbitrary code execution |
| Spawner | env, xargs, find -exec | Spawn other processes |
| Privilege | sudo, su, pkexec | Privilege escalation |

Concrete lists are defined in code as `pub const RISKY_SHELLS`, `pub const RISKY_INTERPRETERS`, etc. See documentation for current lists.

**Usage:**

```rust
// Default: risky binaries denied even if allowlisted
let policy = ProcPolicy::builder()
    .allow_bin("/bin/bash")  // Will still be denied
    .build()?;
policy.prepare(bash_request);  // ❌ E_BIN_RISKY_DENIED

// Explicit opt-in with warning
let policy = ProcPolicy::builder()
    .risky_bin_policy(RiskyBinPolicy::AllowWithWarning)
    .allow_bin("/bin/bash")
    .build()?;
policy.prepare(bash_request);  // ⚠️ Allowed, logs warning
```

**Rationale:** Defense in depth against accidental allowlisting of dangerous binaries.

### R7 — Argument Rules Required

Every allowed binary **MUST** have an `ArgRules` entry. There is no "allow any args" mode.

```rust
let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    // No arg_rules for grep
    .build();
// ❌ Error: ArgRules required for /usr/bin/grep

let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    .arg_rules("/usr/bin/grep", ArgRules::new()
        .allowed_flags(&["-n", "-i"])
        .max_positionals(5))
    .build()?;
// ✅ OK
```

**Rationale:** "Allow binary with any args" defeats the purpose of proc_jail. If you want that, use `std::process::Command` directly.

### R8 — Argument Rules (Allowlist Only)

`ArgRules` uses **allowlist-only** flag validation. There is no denylist.

```rust
pub struct ArgRules {
    /// Required first positional (subcommand pinning)
    pub subcommand: Option<String>,
    
    /// Allowed flags (exact match). Empty = no flags allowed.
    pub allowed_flags: HashSet<String>,
    
    /// Maximum number of flags
    pub max_flags: usize,
    
    /// Maximum number of positional arguments (excluding subcommand)
    pub max_positionals: usize,
    
    /// Double-dash injection mode
    pub inject_double_dash: InjectDoubleDash,
}

impl Default for ArgRules {
    fn default() -> Self {
        Self {
            subcommand: None,
            allowed_flags: HashSet::new(),  // No flags allowed by default
            max_flags: 0,
            max_positionals: 0,
            inject_double_dash: InjectDoubleDash::Never,
        }
    }
}
```

**Why no denylist:**

Denylists fail. Blocking `-f` doesn't block `--file`. Blocking `--file` doesn't block `--file=value`. You will chase flag aliases forever. Allowlists are verbose but correct.

```rust
// ✅ Allowlist: explicit about what's permitted
allowed_flags: hashset!["-n", "-i", "-l", "-c", "--color=never"]

// ❌ No denylist - removed from spec
denied_flags: hashset!["-f", "--file"]  // This API doesn't exist
```

**Rationale:** High-assurance requires explicit enumeration. Verbosity is a feature.

### R9 — Double-Dash Injection

When enabled, proc_jail inserts `--` to separate flags from positionals.

```rust
pub enum InjectDoubleDash {
    /// Never inject (default)
    Never,
    
    /// Inject after validated flags, before first positional
    /// Only if at least one positional argument exists
    AfterFlags,
}
```

**Injection rules:**

1. Only inject if mode is `AfterFlags`
2. Only inject if there is at least one positional argument
3. Insert `--` after the last flag, before the first positional
4. If no flags present but positionals exist, insert `--` at the beginning

```rust
let rules = ArgRules::new()
    .allowed_flags(&["-r", "-n", "-i"])
    .inject_double_dash(InjectDoubleDash::AfterFlags);

// Input: ["-r", "-n", "pattern", user_input, "dir/"]
// After: ["-r", "-n", "--", "pattern", user_input, "dir/"]

// Input: ["pattern", user_input]  (no flags)
// After: ["--", "pattern", user_input]

// Input: ["-r", "-n"]  (no positionals)
// After: ["-r", "-n"]  (no injection)
```

**Limitations:**

- Only effective for tools that respect POSIX `--` convention
- May break tools with non-standard argument parsing
- Test with your specific binaries

**Rationale:** Prevents flag injection via user-controlled positional arguments.

### R10 — Environment Control

Policy **MUST** control the environment.

```rust
pub enum EnvPolicy {
    /// Pass empty environment map to execve (default)
    Empty,
    
    /// Locale only: LANG=C.UTF-8, LC_ALL=C.UTF-8
    LocaleOnly,
    
    /// Explicit fixed values (fully specified)
    Fixed(HashMap<String, String>),
    
    /// Allowlist keys from request (still applies ALWAYS_STRIP)
    AllowList(HashSet<String>),
}
```

**Default:** `EnvPolicy::Empty`

**Semantics of `Empty`:**

`EnvPolicy::Empty` means proc_jail passes an empty environment map to `execve`. The spawned process inherits no environment variables from the parent. Note: libc or the kernel may inject minimal implicit state (e.g., on some systems), but no user-controlled environment is passed.

**ALWAYS_STRIP variables:**

These variables are **always** removed, even with `EnvPolicy::AllowList`:

| Category | Variables |
|----------|-----------|
| Library injection | `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_*` |
| Interpreter paths | `PYTHONPATH`, `RUBYLIB`, `PERL5LIB`, `NODE_PATH`, etc. |
| Shell behavior | `BASH_ENV`, `ENV`, `SHELLOPTS`, `IFS`, `CDPATH` |
| Proxy hijacking | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, etc. |
| Execution | `EDITOR`, `VISUAL`, `PAGER`, `PROMPT_COMMAND` |

Full list defined in code as `pub const ALWAYS_STRIP`.

**Note:** `PATH` is not included in any default policy. Since R2 requires absolute paths, `PATH` is unnecessary.

**Rationale:** Prevents environment-based behavior changes.

### R11 — Working Directory Control

Policy **MUST** control cwd.

```rust
pub enum CwdPolicy {
    /// Fixed directory (default)
    Fixed(AbsolutePath),
    
    /// Must be within a jail (integrates with path_jail)
    Jailed(PathJail),
    
    /// Allowlist of directories
    AllowList(HashSet<AbsolutePath>),
}
```

**Default:** `CwdPolicy::Fixed("/tmp")` or policy-specified directory.

**Rationale:** Many tools interpret relative paths; cwd determines their scope.

### R12 — Resource Limits

Policy **MUST** provide deterministic limits.

```rust
pub struct ResourceLimits {
    /// Wall-clock timeout
    pub timeout: Duration,
    
    /// Maximum stdout bytes
    pub max_stdout: usize,
    
    /// Maximum stderr bytes  
    pub max_stderr: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_stdout: 10 * 1024 * 1024,  // 10 MB
            max_stderr: 1 * 1024 * 1024,   // 1 MB
        }
    }
}
```

**Kill behavior:**

When any limit is exceeded:

1. proc_jail sends `SIGKILL` to the spawned process (Unix)
2. Partial output up to the limit is captured and returned
3. Returns appropriate `ExecError` variant

**Child process note:** Only the direct child is killed. Grandchild processes are NOT automatically killed. For full process tree termination, use process groups or container isolation.

**v0.1 scope:** Only `Kill` behavior is supported. `Truncate` (allow process to continue, truncate output) is deferred to v0.2.

**Rationale:** Prevents hangs, runaway output, log bombs, resource exhaustion.

### R13 — Fail Closed

- Any parsing error, policy mismatch, or evaluation failure **MUST** deny execution
- Canonicalization failures **MUST** deny execution
- Missing `ArgRules` **MUST** deny execution (not fail-open)
- Errors **MUST** be safe to log (no secrets in error messages)

---

## Error Taxonomy

```rust
pub enum Violation {
    // Binary errors
    BinNotAbsolute { path: String },
    BinNotFound { path: String },
    BinCanonicalizeFailed { path: String, reason: String },
    BinNotAllowed { path: String, canonical: String },
    BinRiskyDenied { path: String, category: RiskCategory },
    BinIsDirectory { path: String },
    BinNotRegularFile { path: String },
    BinNotExecutable { path: String },
    
    // Argument errors
    ArgRulesRequired { bin: String },
    ArgSubcommandMismatch { expected: String, got: Option<String> },
    ArgFlagNotAllowed { flag: String },
    ArgTooManyFlags { max: usize, got: usize },
    ArgTooManyPositionals { max: usize, got: usize },
    
    // Environment errors
    EnvForbidden { key: String, reason: &'static str },
    
    // Working directory errors
    CwdForbidden { path: String, reason: String },
}

pub enum RiskCategory {
    Shell,
    Interpreter,
    Spawner,
    Privilege,
}

pub enum ExecError {
    Timeout { limit: Duration, elapsed: Duration },
    StdoutLimitExceeded { limit: usize },
    StderrLimitExceeded { limit: usize },
    SpawnFailed { reason: String },
    NonZeroExit { code: i32, stderr: String },
}
```

---

## Builder API

```rust
let policy = ProcPolicy::builder()
    // Binaries (each requires arg_rules)
    .allow_bin("/usr/bin/grep")
    .allow_bin("/usr/bin/git")
    .allow_bin("/usr/bin/jq")
    
    // Risky binary handling
    .risky_bin_policy(RiskyBinPolicy::DenyByDefault)
    
    // Argument rules (REQUIRED for each binary)
    .arg_rules("/usr/bin/git", ArgRules::new()
        .subcommand("status")
        .allowed_flags(&["--porcelain", "-sb"])
        .max_flags(2)
        .max_positionals(0))
    
    .arg_rules("/usr/bin/grep", ArgRules::new()
        .allowed_flags(&["-n", "-i", "-l", "-c", "--color=never"])
        .max_flags(5)
        .max_positionals(10)
        .inject_double_dash(InjectDoubleDash::AfterFlags))
    
    .arg_rules("/usr/bin/jq", ArgRules::new()
        .allowed_flags(&["-r", "-c", "-e", "--raw-output"])
        .max_flags(3)
        .max_positionals(2))
    
    // Environment
    .env_policy(EnvPolicy::LocaleOnly)
    
    // Working directory
    .cwd_policy(CwdPolicy::Fixed("/srv/workspace".into()))
    
    // Limits
    .timeout(Duration::from_secs(30))
    .max_stdout(1024 * 1024)
    .max_stderr(256 * 1024)
    
    .build()?;  // Returns error if any allowed_bin lacks arg_rules
```

---

## Usage Examples

### Example A — Shell Injection Becomes Impossible

**Vulnerable pattern:**

```python
# Python - vulnerable
subprocess.run(f"grep '{query}' file.txt", shell=True)

# Attacker: query = "x'; rm -rf / #"
# Executes: grep 'x'; rm -rf / #' file.txt
```

**With proc_jail:**

```rust
let request = ProcRequest {
    bin: "/usr/bin/grep".into(),
    argv: vec![query.clone(), "file.txt".into()],
    ..Default::default()
};

let output = policy.prepare(request)?.spawn().await?;

// If query = "x'; rm -rf / #"
// Executes: grep "x'; rm -rf / #" file.txt
// The injection is just a literal string, not interpreted
```

### Example B — Symlink Attack Prevented

```rust
// Attacker creates: /tmp/safe_tool -> /bin/bash

let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    .arg_rules("/usr/bin/grep", ArgRules::new().max_positionals(2))
    .build()?;

let request = ProcRequest {
    bin: "/tmp/safe_tool".into(),
    argv: vec!["-c".into(), "malicious".into()],
    ..Default::default()
};

let result = policy.prepare(request);
// Canonicalization: /tmp/safe_tool -> /bin/bash
// /bin/bash not in allowlist
// ❌ Err(Violation::BinNotAllowed { path: "/tmp/safe_tool", canonical: "/bin/bash" })
```

### Example C — Subcommand Pinning

```rust
let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/git")
    .arg_rules("/usr/bin/git", ArgRules::new()
        .subcommand("status")
        .allowed_flags(&["--porcelain", "-sb"])
        .max_flags(2)
        .max_positionals(0))
    .build()?;

// ✅ Allowed
policy.prepare(request("/usr/bin/git", &["status", "--porcelain"]))?;

// ❌ ArgSubcommandMismatch
policy.prepare(request("/usr/bin/git", &["push", "origin", "main"]))?;
```

### Example D — Double-Dash Injection

```rust
let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    .arg_rules("/usr/bin/grep", ArgRules::new()
        .allowed_flags(&["-r", "-n", "-i"])
        .max_flags(3)
        .max_positionals(5)
        .inject_double_dash(InjectDoubleDash::AfterFlags))
    .build()?;

// User input that looks like flags
let user_input = "-e malicious --include=*.secret";

let request = ProcRequest {
    bin: "/usr/bin/grep".into(),
    argv: vec![
        "-r".into(),
        "-n".into(),
        "pattern".into(),
        user_input.into(),
        "dir/".into(),
    ],
    ..Default::default()
};

let prepared = policy.prepare(request)?;
// Argv after injection:
// ["-r", "-n", "--", "pattern", "-e malicious --include=*.secret", "dir/"]
```

### Example E — Allowlist-Only Flags

```rust
// Want to allow grep with specific flags only

let policy = ProcPolicy::builder()
    .allow_bin("/usr/bin/grep")
    .arg_rules("/usr/bin/grep", ArgRules::new()
        .allowed_flags(&["-n", "-i", "-l", "-c"])
        .max_flags(4)
        .max_positionals(10)
        .inject_double_dash(InjectDoubleDash::AfterFlags))
    .build()?;

// ✅ Allowed
policy.prepare(request("/usr/bin/grep", &["-n", "-i", "pattern", "file.txt"]))?;

// ❌ ArgFlagNotAllowed { flag: "-f" }
policy.prepare(request("/usr/bin/grep", &["-f", "/etc/passwd", ".", "dir/"]))?;

// ❌ ArgFlagNotAllowed { flag: "--file" }
policy.prepare(request("/usr/bin/grep", &["--file=/etc/passwd", ".", "dir/"]))?;

// ❌ ArgFlagNotAllowed { flag: "-r" }
policy.prepare(request("/usr/bin/grep", &["-r", "pattern", "/"]))?;
```

---

## Integration with Tenuo Ecosystem

### Complete Agent Tool Example

```rust
use tenuo::Warrant;
use path_jail::PathJail;
use proc_jail::{ProcPolicy, ProcRequest, ArgRules, InjectDoubleDash};

/// Search logs tool for AI agent
async fn search_logs(
    query: &str,
    log_file: &str,
    warrant: &Warrant,
) -> Result<String, ToolError> {
    // 1. Tenuo: Check authorization
    warrant.check("tool:search_logs", &format!("file:{}", log_file))?;
    
    // 2. path_jail: Validate file path
    let jail = PathJail::new("/var/log/app")?;
    let safe_path = jail.join(log_file)?;
    
    // 3. proc_jail: Execute safely
    let policy = get_grep_policy();
    let request = ProcRequest {
        bin: "/usr/bin/grep".into(),
        argv: vec![
            "-n".into(),
            query.into(),
            safe_path.to_string(),
        ],
        ..Default::default()
    };
    
    let output = policy.prepare(request)?.spawn().await?;
    
    Ok(String::from_utf8_lossy(&output.stdout).into())
}

fn get_grep_policy() -> ProcPolicy {
    ProcPolicy::builder()
        .allow_bin("/usr/bin/grep")
        .arg_rules("/usr/bin/grep", ArgRules::new()
            .allowed_flags(&["-n", "-i", "-l", "-c", "--color=never"])
            .max_flags(5)
            .max_positionals(10)
            .inject_double_dash(InjectDoubleDash::AfterFlags))
        .env_policy(EnvPolicy::LocaleOnly)
        .cwd_policy(CwdPolicy::Fixed("/var/log/app".into()))
        .timeout(Duration::from_secs(10))
        .max_stdout(1024 * 1024)
        .build()
        .expect("valid policy")
}
```

### Future: Warrant-Derived Policies

```rust
// v0.2+ vision: Policy derived from cryptographically signed warrant
let warrant = Tenuo::verify(token)?;
let policy = ProcPolicy::from_warrant(&warrant)?;
// Warrant contains allowed_bins and arg_rules, signed by authority
```

### Integration Matrix

| Crate | Integration Point |
|-------|-------------------|
| **Tenuo** | Authorize tool call before proc_jail validates |
| **path_jail** | Validate file paths in arguments and cwd |
| **url_jail** | Validate URLs if needed (prefer disallowing such binaries) |

---

## Security Notes

### 1. TOCTOU Race Condition

There is a Time-of-Check to Time-of-Use race between `prepare()` (canonicalization) and `spawn()` (execution). An attacker with local filesystem write access could swap the binary between these calls.

**proc_jail does NOT protect against this.** This library defends against application-level injection attacks, not local privilege escalation.

**Mitigations:**
- Use read-only mounts for binary directories
- Use container isolation
- Use immutable infrastructure

### 2. Allowed binaries may spawn subprocesses

Some allowed binaries can spawn other processes:

| Binary | Subprocess Risk |
|--------|-----------------|
| `git` | Hooks (`.git/hooks/*`), config aliases |
| `make` | Executes shell commands |
| `npm` | postinstall scripts |
| Compilers | Preprocessors, linkers |

proc_jail controls the top-level spawn only. For high-risk cases:
- Disable hooks via arguments or environment
- Pin subcommands to safe operations
- Use seccomp/containers

### 3. Prefer narrow, non-extensible binaries

```rust
// ✅ Good - single-purpose, no extension mechanism
"/usr/bin/jq", "/usr/bin/grep", "/usr/bin/wc", "/usr/bin/head"

// ⚠️ Risky - has extension/hook mechanisms
"/usr/bin/git", "/usr/bin/make", "/usr/bin/npm"
```

### 4. Allowlist verbosity is intentional

Writing out every allowed flag is tedious. This is by design. If it feels like too much work, consider whether you need that binary at all. proc_jail is for high-assurance agents where security matters more than convenience.

### 5. Double-dash is best-effort

The `inject_double_dash` feature only works for tools that follow POSIX conventions. Test with your specific binaries.

### 6. Kill does not kill grandchildren

When proc_jail kills a process (timeout, output limit), only the direct child receives SIGKILL. Grandchild processes may continue running. For full process tree termination, use process groups or containers.

### 7. Risky binary list is advisory

The built-in risky binary categories catch common mistakes but are not exhaustive. Don't rely on them as your only defense.

---

## Required Test Cases

### Binary Validation

```rust
#[test] fn absolute_path_required() { }
#[test] fn relative_path_rejected() { }
#[test] fn symlink_resolves_to_allowed() { }
#[test] fn symlink_resolves_to_disallowed() { }
#[test] fn broken_symlink_rejected() { }
#[test] fn nonexistent_binary_rejected() { }
#[test] fn directory_rejected() { }
#[test] fn device_file_rejected() { }
#[test] fn non_executable_rejected() { }
#[test] fn risky_binary_denied_by_default() { }
#[test] fn risky_binary_allowed_with_warning() { }
```

### Argument Validation

```rust
#[test] fn arg_rules_required_for_each_binary() { }
#[test] fn subcommand_mismatch_rejected() { }
#[test] fn flag_not_in_allowlist_rejected() { }
#[test] fn too_many_flags_rejected() { }
#[test] fn too_many_positionals_rejected() { }
#[test] fn double_dash_injected_after_flags() { }
#[test] fn double_dash_injected_at_start_if_no_flags() { }
#[test] fn double_dash_not_injected_if_no_positionals() { }
#[test] fn stdin_dash_treated_as_positional() { }
```

### Environment

```rust
#[test] fn empty_env_passes_nothing() { }
#[test] fn locale_only_passes_lang_lc_all() { }
#[test] fn always_strip_applied_even_with_allowlist() { }
#[test] fn ld_preload_always_stripped() { }
```

### Resource Limits

```rust
#[test] fn timeout_kills_process() { }
#[test] fn stdout_limit_kills_process() { }
#[test] fn stderr_limit_kills_process() { }
#[test] fn partial_output_captured_before_kill() { }
```

---

## v0.1 Scope

### Included

- Unix only (Linux, macOS)
- `ProcPolicy` with allowlisted absolute binaries
- Path canonicalization with symlink resolution
- Regular file and executable checks
- `RiskyBinPolicy`: DenyByDefault, AllowWithWarning, Disabled
- Mandatory `ArgRules` for each binary
- Allowlist-only flag validation (no denylist)
- `max_flags` and `max_positionals` limits
- `InjectDoubleDash`: Never, AfterFlags
- `EnvPolicy`: Empty, LocaleOnly, Fixed, AllowList
- `ALWAYS_STRIP` environment variables
- `CwdPolicy`: Fixed, Jailed, AllowList
- `ResourceLimits`: timeout, max stdout/stderr (Kill only)
- Type-safe API: `prepare() -> PreparedCommand`
- Comprehensive error types

### Excluded (v0.2+)

- Windows support
- `LimitBehavior::Truncate`
- Pipeline support (explicit command chains)
- Flag pattern matching (`--file=*`)
- Combined short flag expansion (`-abc` → `-a -b -c`)
- `--flag value` splitting
- Warrant-derived policies
- Binary verification by hash
- uid/gid dropping
- Memory/CPU limits

---

## File Structure

```
proc_jail/
├── Cargo.toml
├── README.md
├── docs/
│   ├── windows.md          # Why Windows is unsupported
│   └── risky-binaries.md   # Current risky binary lists
├── src/
│   ├── lib.rs              # Public API, platform check
│   ├── policy.rs           # ProcPolicy, builder
│   ├── arg_rules.rs        # ArgRules, flag parsing
│   ├── arg_parser.rs       # Argument classification
│   ├── double_dash.rs      # Double-dash injection
│   ├── env_policy.rs       # EnvPolicy, ALWAYS_STRIP
│   ├── cwd_policy.rs       # CwdPolicy
│   ├── limits.rs           # ResourceLimits
│   ├── request.rs          # ProcRequest
│   ├── prepared.rs         # PreparedCommand, spawn
│   ├── canonical.rs        # Path canonicalization
│   ├── file_check.rs       # Regular file, executable checks
│   ├── risky.rs            # RiskyBinPolicy, category lists
│   ├── error.rs            # Violation, ExecError
│   └── output.rs           # Output capture
└── tests/
    ├── binary_validation.rs
    ├── arg_validation.rs
    ├── env_policy.rs
    ├── resource_limits.rs
    └── integration.rs
```

---

## License

MIT OR Apache-2.0
