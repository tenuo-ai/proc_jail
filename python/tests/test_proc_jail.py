"""Tests for proc_jail Python bindings."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Skip all tests on Windows
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="proc_jail is Unix-only"
)

from proc_jail import (
    ArgRules,
    InjectDoubleDash,
    Output,
    PreparedCommand,
    ProcPolicy,
    ProcPolicyBuilder,
    ProcRequest,
    RiskCategory,
    RiskyBinPolicy,
)


class TestArgRules:
    """Test ArgRules builder."""

    def test_create_empty(self):
        rules = ArgRules()
        assert rules is not None

    def test_builder_chain(self):
        rules = (
            ArgRules()
            .allowed_flags(["-n", "-i", "--color=never"])
            .max_flags(3)
            .max_positionals(10)
            .inject_double_dash(InjectDoubleDash.AfterFlags)
        )
        assert rules is not None

    def test_subcommand(self):
        rules = ArgRules().subcommand("status").max_positionals(0)
        assert rules is not None


class TestProcRequest:
    """Test ProcRequest."""

    def test_create_simple(self):
        request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
        assert request.bin == "/usr/bin/grep"
        assert request.argv == ["-n", "pattern", "file.txt"]

    def test_with_cwd(self):
        request = ProcRequest("/usr/bin/grep", []).with_cwd("/tmp")
        assert request is not None

    def test_with_env(self):
        request = ProcRequest("/usr/bin/grep", []).with_env({"FOO": "bar"})
        assert request is not None

    def test_with_env_var(self):
        request = ProcRequest("/usr/bin/grep", []).with_env_var("FOO", "bar")
        assert request is not None


class TestProcPolicyBuilder:
    """Test ProcPolicyBuilder."""

    def test_create_empty(self):
        builder = ProcPolicyBuilder()
        assert builder is not None

    def test_builder_chain(self):
        builder = (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/grep")
            .arg_rules(
                "/usr/bin/grep",
                ArgRules()
                .allowed_flags(["-n", "-i"])
                .max_flags(2)
                .max_positionals(10),
            )
            .timeout_secs(30)
            .max_stdout(1024 * 1024)
            .max_stderr(256 * 1024)
            .cwd("/tmp")
            .env_locale_only()
        )
        assert builder is not None

    def test_build_without_arg_rules_fails(self):
        builder = ProcPolicyBuilder().allow_bin("/usr/bin/grep")
        with pytest.raises(ValueError, match="argument rules required"):
            builder.build()

    def test_build_nonexistent_binary_fails(self):
        builder = (
            ProcPolicyBuilder()
            .allow_bin("/nonexistent/binary")
            .arg_rules("/nonexistent/binary", ArgRules())
        )
        with pytest.raises(ValueError, match="not found"):
            builder.build()


class TestProcPolicy:
    """Test ProcPolicy."""

    @pytest.fixture
    def grep_policy(self):
        """Create a policy for grep."""
        return (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/grep")
            .arg_rules(
                "/usr/bin/grep",
                ArgRules()
                .allowed_flags(["-n", "-i", "-l", "-c", "-r", "-E", "--color=never"])
                .max_flags(5)
                .max_positionals(10)
                .inject_double_dash(InjectDoubleDash.AfterFlags),
            )
            .timeout_secs(5)
            .cwd("/tmp")
            .env_locale_only()
            .build()
        )

    def test_prepare_valid_request(self, grep_policy):
        request = ProcRequest("/usr/bin/grep", ["-n", "pattern", "file.txt"])
        prepared = grep_policy.prepare(request)
        assert isinstance(prepared, PreparedCommand)
        assert prepared.bin.endswith("grep")
        # Should have -- injected
        assert "--" in prepared.argv

    def test_prepare_disallowed_binary(self, grep_policy):
        request = ProcRequest("/bin/ls", [])
        with pytest.raises(ValueError, match="not allowed"):
            grep_policy.prepare(request)

    def test_prepare_disallowed_flag(self, grep_policy):
        request = ProcRequest("/usr/bin/grep", ["-f", "/etc/passwd"])
        with pytest.raises(ValueError, match="not allowed"):
            grep_policy.prepare(request)

    def test_prepare_too_many_flags(self, grep_policy):
        request = ProcRequest(
            "/usr/bin/grep",
            ["-n", "-i", "-l", "-c", "-r", "-E", "pattern"],
        )
        with pytest.raises(ValueError, match="too many flags"):
            grep_policy.prepare(request)

    def test_prepare_relative_path_rejected(self, grep_policy):
        request = ProcRequest("grep", ["-n", "pattern"])
        with pytest.raises(ValueError, match="absolute"):
            grep_policy.prepare(request)


class TestRiskyBinaryPolicy:
    """Test risky binary handling."""

    def test_shell_denied_by_default(self):
        policy = (
            ProcPolicyBuilder()
            .allow_bin("/bin/bash")
            .arg_rules("/bin/bash", ArgRules())
            .build()
        )
        request = ProcRequest("/bin/bash", [])
        with pytest.raises(ValueError, match="risky"):
            policy.prepare(request)

    def test_shell_allowed_with_disabled_policy(self):
        policy = (
            ProcPolicyBuilder()
            .allow_bin("/bin/bash")
            .arg_rules("/bin/bash", ArgRules()
                .allowed_flags(["-c"])
                .max_flags(1)
                .max_positionals(1))
            .risky_bin_policy(RiskyBinPolicy.Disabled)
            .build()
        )
        request = ProcRequest("/bin/bash", ["-c", "echo hello"])
        # Should not raise
        prepared = policy.prepare(request)
        assert prepared is not None


class TestExecution:
    """Test actual command execution."""

    @pytest.fixture
    def echo_policy(self):
        """Create a policy for echo."""
        return (
            ProcPolicyBuilder()
            .allow_bin("/bin/echo")
            .arg_rules(
                "/bin/echo",
                ArgRules().allowed_flags(["-n"]).max_flags(1).max_positionals(10),
            )
            .timeout_secs(5)
            .build()
        )

    def test_execute_echo(self, echo_policy):
        request = ProcRequest("/bin/echo", ["hello", "world"])
        prepared = echo_policy.prepare(request)
        output = prepared.spawn_sync()

        assert output.success
        assert output.exit_code == 0
        assert "hello world" in output.stdout_string()

    def test_execute_with_shell_chars(self, echo_policy):
        """Shell metacharacters should be treated as literals."""
        request = ProcRequest("/bin/echo", ["hello; rm -rf /"])
        prepared = echo_policy.prepare(request)
        output = prepared.spawn_sync()

        assert output.success
        # The shell command should be echoed literally
        assert "hello; rm -rf /" in output.stdout_string()

    def test_timeout(self):
        """Test that timeout kills the process."""
        policy = (
            ProcPolicyBuilder()
            .allow_bin("/bin/sleep")
            .arg_rules("/bin/sleep", ArgRules().max_positionals(1))
            .timeout_secs(1)
            .build()
        )
        request = ProcRequest("/bin/sleep", ["10"])
        prepared = policy.prepare(request)

        with pytest.raises(RuntimeError, match="timed out"):
            prepared.spawn_sync()


class TestSubcommandPinning:
    """Test subcommand pinning."""

    @pytest.fixture
    def git_status_policy(self):
        """Create a policy for git status only."""
        if not os.path.exists("/usr/bin/git"):
            pytest.skip("git not installed")
        return (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/git")
            .arg_rules(
                "/usr/bin/git",
                ArgRules()
                .subcommand("status")
                .allowed_flags(["--porcelain", "-s"])
                .max_flags(2)
                .max_positionals(0),
            )
            .cwd("/tmp")
            .build()
        )

    def test_correct_subcommand_allowed(self, git_status_policy):
        request = ProcRequest("/usr/bin/git", ["status"])
        prepared = git_status_policy.prepare(request)
        assert prepared is not None

    def test_wrong_subcommand_rejected(self, git_status_policy):
        request = ProcRequest("/usr/bin/git", ["push"])
        with pytest.raises(ValueError, match="subcommand"):
            git_status_policy.prepare(request)


class TestEnvPolicy:
    """Test environment policy."""

    def test_env_empty(self):
        policy = (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/env")
            .arg_rules("/usr/bin/env", ArgRules())
            .risky_bin_policy(RiskyBinPolicy.Disabled)
            .env_empty()
            .build()
        )
        request = ProcRequest("/usr/bin/env", [])
        prepared = policy.prepare(request)
        output = prepared.spawn_sync()

        # With empty env, /usr/bin/env should print nothing
        assert output.stdout_string().strip() == ""

    def test_env_locale_only(self):
        policy = (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/env")
            .arg_rules("/usr/bin/env", ArgRules())
            .risky_bin_policy(RiskyBinPolicy.Disabled)
            .env_locale_only()
            .build()
        )
        request = ProcRequest("/usr/bin/env", [])
        prepared = policy.prepare(request)
        output = prepared.spawn_sync()

        stdout = output.stdout_string()
        assert "LANG=C.UTF-8" in stdout
        assert "LC_ALL=C.UTF-8" in stdout


class TestDoubleDashInjection:
    """Test double-dash injection."""

    def test_double_dash_injected(self):
        policy = (
            ProcPolicyBuilder()
            .allow_bin("/bin/echo")
            .arg_rules(
                "/bin/echo",
                ArgRules()
                .allowed_flags(["-n"])
                .max_flags(1)
                .max_positionals(10)
                .inject_double_dash(InjectDoubleDash.AfterFlags),
            )
            .build()
        )
        request = ProcRequest("/bin/echo", ["-n", "hello"])
        prepared = policy.prepare(request)

        # Should have -- after -n, before hello
        assert "--" in prepared.argv
        assert prepared.argv.index("--") > prepared.argv.index("-n")
        assert prepared.argv.index("--") < prepared.argv.index("hello")


class TestSymlinkResolution:
    """Test symlink handling."""

    def test_symlink_to_allowed_binary(self, tmp_path):
        """Symlink to allowed binary should work."""
        link_path = tmp_path / "my_grep"
        link_path.symlink_to("/usr/bin/grep")

        policy = (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/grep")
            .arg_rules(
                "/usr/bin/grep",
                ArgRules().allowed_flags(["-n"]).max_flags(1).max_positionals(2),
            )
            .build()
        )

        request = ProcRequest(str(link_path), ["-n", "pattern"])
        # Should resolve symlink and match allowlist
        prepared = policy.prepare(request)
        assert prepared is not None

    def test_symlink_to_disallowed_binary(self, tmp_path):
        """Symlink to disallowed binary should be rejected."""
        link_path = tmp_path / "safe_tool"
        link_path.symlink_to("/bin/bash")

        policy = (
            ProcPolicyBuilder()
            .allow_bin("/usr/bin/grep")
            .arg_rules(
                "/usr/bin/grep",
                ArgRules().max_positionals(2),
            )
            .build()
        )

        request = ProcRequest(str(link_path), ["-c", "echo pwned"])
        with pytest.raises(ValueError, match="not allowed|risky"):
            policy.prepare(request)

