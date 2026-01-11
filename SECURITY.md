# Security

This document describes the security properties and known limitations of `proc_jail`.

## Security Properties

### What proc_jail Guarantees

1. **No shell interpretation**: Commands are executed via `execve` with an argv array. Shell metacharacters (`;`, `|`, `$()`, etc.) are never interpreted.

2. **Binary allowlist enforcement**: Only explicitly allowed binaries can be executed. Canonicalization resolves symlinks before comparison.

3. **Argument validation**: Flags must be explicitly allowed. Positional counts are enforced. No implicit flag expansion.

4. **Environment isolation**: By default, no environment variables are passed. Dangerous variables (LD_PRELOAD, PYTHONPATH, etc.) are always stripped.

5. **Resource bounds**: Timeout and output limits are enforced. Exceeding limits kills the process.

6. **Fail closed**: Any validation failure, ambiguity, or error results in denial.

### What proc_jail Does NOT Guarantee

1. **Syscall-level sandboxing**: proc_jail does not restrict what syscalls the spawned process can make. Use seccomp, AppArmor, or containers for that.

2. **Binary safety**: An allowed binary may have bugs, vulnerabilities, or dangerous features. proc_jail only controls which binary runs and with what arguments.

3. **Subprocess control**: Allowed binaries can spawn their own subprocesses. proc_jail only controls the top-level spawn.

4. **Memory/CPU limits**: Only wall-clock timeout and output byte limits are enforced. Use cgroups for memory/CPU limits.

5. **Privilege boundaries**: proc_jail runs with your privileges. It does not drop capabilities or change uid/gid.

## Known Limitations

### TOCTOU Race Condition

There is a time-of-check to time-of-use race between `prepare()` (which canonicalizes the binary path) and `spawn()` (which executes it).

An attacker with **local filesystem write access** could:
1. Create a symlink to an allowed binary
2. Call `prepare()` (symlink resolves to allowed binary)
3. Replace the symlink target with a malicious binary
4. `spawn()` executes the malicious binary

**Mitigations**:
- Use immutable infrastructure
- Mount binary directories read-only
- Use container isolation
- Avoid local attackers with filesystem write access

### Grandchild Processes

When proc_jail kills a process (timeout, output limit exceeded), only the direct child receives SIGKILL. Grandchild processes are not killed automatically.

**Mitigations**:
- Use process groups (requires additional code)
- Use containers with proper init
- Set timeout on the container/cgroup level

### Risky Binary List is Advisory

The built-in lists of risky binaries (shells, interpreters, etc.) are not exhaustive. New binaries, version-specific variants, or renamed binaries may not be detected.

**Mitigations**:
- Use `RiskyBinPolicy::DenyByDefault` (the default)
- Audit your allowlist carefully
- Prefer narrow, single-purpose binaries

### Double-Dash is Best-Effort

The `InjectDoubleDash::AfterFlags` feature only works for programs that follow POSIX conventions. Some programs ignore `--` or parse it differently.

**Mitigations**:
- Test with your specific binaries
- Use subcommand pinning where possible
- Validate positional arguments at the application layer

### Allowed Binaries May Have Dangerous Features

Some "safe" binaries have dangerous subcommands or options:

| Binary | Risk |
|--------|------|
| `git` | Hooks in `.git/hooks/`, config aliases |
| `make` | Executes shell commands |
| `curl` | Can write files, execute scripts |
| `tar` | Can overwrite files outside target |

**Mitigations**:
- Pin subcommands (e.g., `git status` only)
- Use restrictive flag allowlists
- Validate paths with `path_jail` before passing to binaries
- Disable hooks via arguments or environment

## Threat Model

### In Scope

- Remote attackers controlling command arguments via prompt injection
- Attackers with knowledge of tool schemas and error feedback
- Multiple adaptive attack attempts

### Out of Scope

- Compromised host OS
- Local attackers with filesystem write access
- Kernel exploits
- Side-channel attacks
- RCE vulnerabilities in allowed binaries
- Natural language intent interpretation

## Reporting Security Issues

If you discover a security vulnerability in proc_jail, please report it privately. Do not open a public issue.

**Email**: security@tenuo.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)


## Security Checklist for Users

Before deploying proc_jail:

- [ ] Audit your binary allowlist
- [ ] Verify flag allowlists are minimal
- [ ] Test double-dash injection with your specific binaries
- [ ] Consider container isolation for defense in depth
- [ ] Review allowed binaries for dangerous features (hooks, subcommands)
- [ ] Ensure binary directories are read-only if possible
