# Design Decisions

This document explains the rationale behind key design decisions in `proc_jail`.

## Why Allowlist-Only for Flags (No Denylist)

**Decision**: Only explicitly allowed flags pass validation. There is no `denied_flags` option.

**Rationale**:

Denylists fail. Consider trying to block the `-f` flag (read patterns from file):

```rust
// ❌ WRONG: Denylist approach
denied_flags: ["-f"]
```

An attacker can bypass this with:
- `--file` (long form)
- `--file=patterns.txt` (with value)
- `-F` (case variation on some systems)
- `--regexp-file` (alias)

You will spend forever chasing flag aliases. Every program has different conventions.

**Allowlists are verbose but correct**:

```rust
// ✅ CORRECT: Allowlist approach
allowed_flags: ["-n", "-i", "-l", "-c", "--color=never"]
```

If it's not in the list, it's denied. No surprises.

## Why `-abc` Is Not Expanded to `-a -b -c`

**Decision**: Combined short flags like `-abc` are treated as a single flag, not expanded.

**Rationale**:

1. **No universal standard**: Not all programs support combined flags. Some treat `-abc` as a long flag.

2. **Security over convenience**: Expanding `-abc` to `-a -b -c` could allow unintended combinations. If you allow `-a` and `-b` individually but not together, expansion would violate that intent.

3. **Explicit is safer**: If you want to allow `-a`, `-b`, and `-abc`, add all three to the allowlist.

```rust
// To allow both styles:
allowed_flags: ["-a", "-b", "-c", "-ab", "-abc"]
```

## Why `--flag=value` Doesn't Match `--flag`

**Decision**: `--file=foo.txt` does not match `--file` in the allowlist.

**Rationale**:

The value is part of the flag for security purposes:

```rust
// Only allows --color with "never" value
allowed_flags: ["--color=never"]

"--color=never"  // ✅ Matches
"--color=always" // ❌ Rejected
"--color"        // ❌ Rejected (different flag)
```

If you want to allow any value, you must enumerate them:

```rust
allowed_flags: ["--color=never", "--color=auto", "--color=always"]
```

This prevents attackers from passing unexpected values.

**Future consideration**: v0.2+ may add pattern matching (`--color=*`), but v0.1 requires explicit enumeration.

## Why Absolute Paths Only

**Decision**: Binary paths must be absolute (start with `/`).

**Rationale**:

Relative paths are ambiguous and attackable:

```
"grep"          → Depends on PATH, can be hijacked
"./grep"        → Depends on cwd, can be manipulated
"../bin/grep"   → Depends on cwd, traversal possible
"/usr/bin/grep" → Unambiguous, canonicalizable
```

Since we canonicalize paths anyway, requiring absolute paths upfront:
1. Makes intent clear
2. Fails fast if caller makes a mistake
3. Avoids PATH-based attacks entirely

## Why Canonicalize Before Comparison

**Decision**: Binary paths are resolved (symlinks followed) before comparison to the allowlist.

**Rationale**:

Without canonicalization, this attack works:

```bash
# Attacker creates symlink
ln -s /bin/bash /tmp/safe_tool

# Allowlist contains only /usr/bin/grep
policy.prepare("/tmp/safe_tool")  # Would this work?
```

With canonicalization:
1. `/tmp/safe_tool` resolves to `/bin/bash`
2. `/bin/bash` is not in allowlist
3. Request denied

The canonicalized path represents "what will actually execute."

## Why Environment Is Empty by Default

**Decision**: `EnvPolicy::Empty` is the default—processes inherit no environment.

**Rationale**:

Environment variables can modify behavior in dangerous ways:

| Variable | Risk |
|----------|------|
| `LD_PRELOAD` | Load arbitrary shared libraries |
| `PYTHONPATH` | Load arbitrary Python modules |
| `PATH` | Change which binaries are found |
| `EDITOR` | Execute arbitrary commands |

Secure-by-default means no environment. Callers must opt-in:

```rust
// Explicit choice to pass locale
.env_policy(EnvPolicy::LocaleOnly)

// Explicit choice to pass specific vars
.env_policy(EnvPolicy::Fixed(my_env))
```

## Why Double-Dash Injection Is Optional

**Decision**: Double-dash (`--`) injection is off by default (`InjectDoubleDash::Never`).

**Rationale**:

1. **Not all programs support it**: Some programs ignore `--` or interpret it differently.

2. **May break legitimate use**: If a program doesn't expect `--`, it might fail.

3. **Callers should test first**: Enable only after verifying your target programs handle `--` correctly.

```rust
// Only enable after testing with your specific binaries
.inject_double_dash(InjectDoubleDash::AfterFlags)
```

## Why Kill, Not Truncate, on Limit Exceeded

**Decision**: When output limits are exceeded, the process is killed (SIGKILL).

**Rationale**:

1. **Simpler guarantee**: Caller knows the process is dead, no cleanup needed.

2. **Prevents resource waste**: A truncated process might continue consuming CPU/memory.

3. **Fail-fast philosophy**: Better to fail clearly than silently truncate.

**Future consideration**: v0.2+ may add `LimitBehavior::Truncate` for cases where the caller wants partial output without killing.

## Why PreparedCommand Cannot Be Constructed Directly

**Decision**: `PreparedCommand` has no public constructor. Only `ProcPolicy::prepare()` can create one.

**Rationale**:

This is the "typestate" pattern—the type system enforces the validation workflow:

```rust
// The ONLY way to get a PreparedCommand
let prepared: PreparedCommand = policy.prepare(request)?;

// PreparedCommand::new() doesn't exist
// You cannot bypass validation
```

This eliminates an entire class of bugs where code accidentally spawns unvalidated commands.

