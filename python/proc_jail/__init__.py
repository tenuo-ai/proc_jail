"""proc_jail - Process execution guard for agentic systems."""

from proc_jail._proc_jail import (
    ArgRules,
    InjectDoubleDash,
    Output,
    PreparedCommand,
    ProcPolicy,
    ProcPolicyBuilder,
    ProcRequest,
    RiskCategory,
    RiskyBinPolicy,
    StoppedError,
)

__all__ = [
    "ArgRules",
    "InjectDoubleDash",
    "Output",
    "PreparedCommand",
    "ProcPolicy",
    "ProcPolicyBuilder",
    "ProcRequest",
    "RiskCategory",
    "RiskyBinPolicy",
    "StoppedError",
]

__version__ = "0.3.0"
