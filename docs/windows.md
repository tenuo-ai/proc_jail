# Why Windows is Not Supported

`proc_jail` does not support Windows. This is a fundamental limitation, not a TODO.

## The Problem

On Unix systems, when you spawn a process using `execve`, the kernel receives an **array of arguments**:

```
["grep", "-n", "pattern", "file.txt"]
```

The kernel enforces boundaries between these arguments. There is no way for one argument to "escape" into another. This is physics, not psychology.

On Windows, `CreateProcess` receives a **single command-line string**:

```
"grep -n pattern file.txt"
```

Each program is responsible for parsing this string into arguments. Different programs parse it differently. The rules for quoting, escaping, and splitting are complex and inconsistent.

## Why This Matters

Consider this input from an attacker:

```
pattern = 'foo" "bar'
```

On Unix with execve:
- Argument 2 is exactly: `foo" "bar` (including the quotes)
- No injection possible

On Windows with CreateProcess:
- The command line becomes: `grep -n foo" "bar file.txt`
- Depending on how the target program parses this, it might see:
  - `grep`, `-n`, `foo bar`, `file.txt` (quotes stripped, space preserved)
  - `grep`, `-n`, `foo"`, `"bar`, `file.txt` (different parsing)
  - Something else entirely

There is no universal escaping function that works for all Windows programs.

## What About cmd.exe Escaping?

The Windows command processor (cmd.exe) has its own parsing rules:

- `^` escapes special characters
- `"` grouping is context-dependent
- `%` expansion happens before argument parsing
- Different programs follow different conventions for `\` and `/`

Even if you perfectly escape for cmd.exe, the target program may parse the resulting string differently.

## What About ArgumentList and ProcessStartInfo?

.NET's `ProcessStartInfo.ArgumentList` and similar APIs appear to provide array-style arguments, but they internally convert to a command-line string using standard C runtime conventions. This works for many programs but not all.

Programs that use custom parsers (many do) may interpret the string differently.

## Microsoft's Documentation

From Microsoft's documentation on `CreateProcess`:

> "The Unicode version of this function, CreateProcessW, can modify the contents of this string."

And regarding command-line parsing:

> "The parsing of the arguments is up to the application."

## Our Conclusion

`proc_jail` promises that if you pass an array of arguments, those exact arguments (and only those arguments) will be received by the target process. We cannot make this guarantee on Windows because the boundary between arguments is enforced by convention, not by the kernel.

Rather than provide a false sense of security, we refuse to compile on Windows.

## Alternatives for Windows

If you need secure process execution on Windows:

1. **Use containers**: Run the target in a Windows container or sandbox
2. **Use WSL2**: Run Unix-style process execution inside WSL2
3. **Validate at the application layer**: Ensure your specific target programs parse arguments safely
4. **Use Windows Sandbox**: Isolate the entire process tree

None of these are as clean as Unix execve, but they can provide defense in depth.
