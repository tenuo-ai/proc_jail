# Risky Binaries

`proc_jail` maintains lists of binaries that are considered high-risk. By default, these are blocked even if explicitly added to the allowlist.

## Categories

### Shells

Binaries that can interpret and execute arbitrary commands.

```rust
pub const RISKY_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
];
```

**Risk**: Any shell can execute arbitrary commands via `-c` or similar.

### Interpreters

Script interpreters that can execute arbitrary code.

```rust
pub const RISKY_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3",
    "perl",
    "ruby",
    "node", "nodejs", "deno", "bun",
    "php",
    "lua", "luajit",
    "tclsh", "wish",
    "awk", "gawk", "nawk", "mawk",
];
```

**Risk**: Interpreters can execute arbitrary code passed via arguments or stdin.

### Spawners

Binaries that can spawn other processes.

```rust
pub const RISKY_SPAWNERS: &[&str] = &[
    "env",       // Can run any command with modified environment
    "xargs",     // Executes commands with input as arguments
    "parallel",  // GNU parallel, runs commands in parallel
    "nohup",     // Runs commands immune to hangups
    "timeout",   // Runs commands with timeout
    "time",      // Times command execution
    "nice",      // Runs with modified priority
    "ionice",    // Runs with modified I/O priority
    "strace",    // Traces system calls of command
    "ltrace",    // Traces library calls of command
    "watch",     // Runs command periodically
    "exec",      // Shell builtin to replace process
];
```

**Risk**: These can be used to execute arbitrary binaries, bypassing the allowlist.

### Privilege Escalation

Binaries that can elevate privileges.

```rust
pub const RISKY_PRIVILEGE: &[&str] = &[
    "sudo",      // Execute as another user
    "su",        // Switch user
    "doas",      // OpenBSD sudo alternative
    "pkexec",    // PolicyKit execution
    "gksudo",    // Graphical sudo
    "kdesudo",   // KDE sudo
    "runuser",   // Run as user (root only)
    "chroot",    // Change root directory
];
```

**Risk**: These can escalate privileges or change security context.

## Policy Options

### DenyByDefault (Recommended)

```rust
.risky_bin_policy(RiskyBinPolicy::DenyByDefault)
```

Even if a risky binary is in your allowlist, it will be denied. This catches mistakes like accidentally allowing `/bin/bash`.

### AllowWithWarning

```rust
.risky_bin_policy(RiskyBinPolicy::AllowWithWarning)
```

Risky binaries are allowed if explicitly in the allowlist, but a warning is logged. Use this if you genuinely need to run interpreters and accept the risks.

### Disabled

```rust
.risky_bin_policy(RiskyBinPolicy::Disabled)
```

No special handling. You're on your own. Only use this if you have external security controls.

## Best Practices

1. **Prefer narrow, single-purpose binaries**:
   ```rust
   // Good
   "/usr/bin/jq", "/usr/bin/grep", "/usr/bin/wc", "/usr/bin/head"
   
   // Risky
   "/usr/bin/python3", "/bin/bash"
   ```

2. **If you must use risky binaries**:
   - Use `AllowWithWarning` to get visibility
   - Pin subcommands where possible
   - Use the most restrictive argument rules
   - Consider container isolation

3. **Don't rely solely on this list**:
   - New risky binaries may not be listed
   - Version-specific variants may be missed
   - Symlinks are resolved before checking, but renamed binaries may be missed

4. **Defense in depth**:
   - Use seccomp/AppArmor/SELinux for kernel-level restrictions
   - Run in containers when possible
   - Limit filesystem access with `path_jail`
