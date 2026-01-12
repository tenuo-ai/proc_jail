"""Type stubs for proc_jail."""

from enum import IntEnum

__version__: str

class RiskyBinPolicy(IntEnum):
    """Policy for handling risky binaries (shells, interpreters, etc.)."""
    DenyByDefault = 0
    AllowWithWarning = 1
    Disabled = 2

class InjectDoubleDash(IntEnum):
    """Mode for double-dash injection."""
    Never = 0
    AfterFlags = 1

class RiskCategory(IntEnum):
    """Risk category for dangerous binaries."""
    Shell = 0
    Interpreter = 1
    Spawner = 2
    Privilege = 3

class ArgRules:
    """Rules for validating arguments to a binary.
    
    Example:
        >>> rules = ArgRules()
        >>> rules = rules.allowed_flags(["-n", "-i", "--color=never"])
        >>> rules = rules.max_flags(3)
        >>> rules = rules.max_positionals(10)
        >>> rules = rules.inject_double_dash()  # Defaults to AfterFlags
    """
    
    def __init__(self) -> None: ...
    
    def subcommand(self, cmd: str) -> ArgRules:
        """Set the required subcommand (first positional must match)."""
        ...
    
    def allowed_flags(self, flags: list[str]) -> ArgRules:
        """Set allowed flags from a list."""
        ...
    
    def max_flags(self, max: int) -> ArgRules:
        """Set maximum number of flags."""
        ...
    
    def max_positionals(self, max: int) -> ArgRules:
        """Set maximum number of positional arguments."""
        ...
    
    def inject_double_dash(self, mode: InjectDoubleDash | None = None) -> ArgRules:
        """Set double-dash injection mode.
        
        Args:
            mode: Injection mode. Defaults to AfterFlags if not specified.
        """
        ...

class ProcRequest:
    """A proposed process execution request.
    
    Example:
        >>> request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
        >>> request = request.with_cwd("/tmp")
    """
    
    def __init__(self, bin: str, argv: list[str]) -> None:
        """Create a new request.
        
        Args:
            bin: Absolute path to the binary
            argv: Arguments (not including binary path)
        """
        ...
    
    def with_cwd(self, cwd: str) -> ProcRequest:
        """Set the working directory."""
        ...
    
    def with_env(self, env: dict[str, str]) -> ProcRequest:
        """Set environment variables from a dict."""
        ...
    
    def with_env_var(self, key: str, value: str) -> ProcRequest:
        """Add a single environment variable."""
        ...
    
    @property
    def bin(self) -> str:
        """Get the binary path."""
        ...
    
    @property
    def argv(self) -> list[str]:
        """Get the arguments."""
        ...

class Output:
    """Output from a successfully executed command."""
    
    def stdout_string(self) -> str:
        """Get stdout as string (lossy UTF-8)."""
        ...
    
    def stderr_string(self) -> str:
        """Get stderr as string (lossy UTF-8)."""
        ...
    
    @property
    def stdout(self) -> bytes:
        """Get raw stdout bytes."""
        ...
    
    @property
    def stderr(self) -> bytes:
        """Get raw stderr bytes."""
        ...
    
    @property
    def exit_code(self) -> int | None:
        """Get exit code (if available)."""
        ...
    
    @property
    def success(self) -> bool:
        """Check if process exited successfully."""
        ...

class PreparedCommand:
    """A validated command ready for execution.
    
    This can only be created via ProcPolicy.prepare().
    """
    
    def spawn_sync(self) -> Output:
        """Execute the command synchronously.
        
        Returns:
            Output from the command
        
        Raises:
            RuntimeError: If execution fails (timeout, limit exceeded, spawn failed)
        """
        ...
    
    @property
    def bin(self) -> str:
        """Get the binary path."""
        ...
    
    @property
    def argv(self) -> list[str]:
        """Get the validated arguments."""
        ...
    
    @property
    def cwd(self) -> str:
        """Get the working directory."""
        ...

class ProcPolicyBuilder:
    """Process execution policy builder.
    
    Example:
        >>> policy = (ProcPolicyBuilder()
        ...     .allow_bin("/usr/bin/grep")
        ...     .arg_rules("/usr/bin/grep", ArgRules()
        ...         .allowed_flags(["-n", "-i"])
        ...         .max_flags(2)
        ...         .max_positionals(10)
        ...         .inject_double_dash())
        ...     .timeout(30)
        ...     .build())
    """
    
    def __init__(self) -> None: ...
    
    def allow_bin(self, path: str) -> ProcPolicyBuilder:
        """Add an allowed binary."""
        ...
    
    def arg_rules(self, path: str, rules: ArgRules) -> ProcPolicyBuilder:
        """Set argument rules for a binary."""
        ...
    
    def risky_bin_policy(self, policy: RiskyBinPolicy) -> ProcPolicyBuilder:
        """Set risky binary policy."""
        ...
    
    def allow_risky_binaries(self) -> ProcPolicyBuilder:
        """Allow risky binaries (shells, interpreters, etc.) to be executed.
        
        Convenience method equivalent to .risky_bin_policy(RiskyBinPolicy.Disabled).
        WARNING: Only use if you understand the security implications.
        """
        ...
    
    def env_empty(self) -> ProcPolicyBuilder:
        """Set environment policy to empty (default)."""
        ...
    
    def env_locale_only(self) -> ProcPolicyBuilder:
        """Set environment policy to locale only."""
        ...
    
    def env_fixed(self, env: dict[str, str]) -> ProcPolicyBuilder:
        """Set environment policy to fixed values."""
        ...
    
    def env_allowlist(self, keys: list[str]) -> ProcPolicyBuilder:
        """Set environment policy to allowlist."""
        ...
    
    def cwd(self, path: str) -> ProcPolicyBuilder:
        """Set fixed working directory."""
        ...
    
    def timeout_secs(self, secs: int) -> ProcPolicyBuilder:
        """Set timeout in seconds."""
        ...
    
    def timeout(self, secs: int) -> ProcPolicyBuilder:
        """Set timeout in seconds (convenience alias for timeout_secs)."""
        ...
    
    def max_stdout(self, max: int) -> ProcPolicyBuilder:
        """Set maximum stdout bytes."""
        ...
    
    def max_stderr(self, max: int) -> ProcPolicyBuilder:
        """Set maximum stderr bytes."""
        ...
    
    def build(self) -> ProcPolicy:
        """Build the policy.
        
        Raises:
            ValueError: If policy is invalid (missing arg_rules, bad paths, etc.)
        """
        ...

class ProcPolicy:
    """A built process execution policy."""
    
    def prepare(self, request: ProcRequest) -> PreparedCommand:
        """Validate a request and prepare it for execution.
        
        Args:
            request: The execution request to validate
        
        Returns:
            PreparedCommand ready for execution
        
        Raises:
            ValueError: If the request violates the policy
        """
        ...

