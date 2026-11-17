from __future__ import annotations

from ayentra.ast_analyzer import ASTAnalysisResult, CandidateSuggestion, analyze_source
from ayentra.cloud import (
    UPGRADE_URL,
    is_gating_enforced,
    load_credentials,
    resolve_credentials,
    save_credentials,
)
from ayentra.contracts import (
    InvariantSpec,
    SecurityPrincipal,
    StateSnapshot,
    TransactionPolicy,
    TransitionSpec,
    domain,
    invariant,
    load_toml_invariants,
    load_toml_transitions,
    transition_invariant,
)
from ayentra.engine import EngineCheckResult, InvariantViolation, run_verification_engine
from ayentra.repair import PatchVerificationResult, generate_and_verify_patch
from ayentra.report import VerificationReport, build_verification_report
from ayentra.sarif import build_sarif_report, to_sarif
from ayentra.studio import StudioHandler, create_studio_server, execute_full_check, run_studio_server

__version__ = "1.0.1"

__all__ = [
    "ASTAnalysisResult",
    "CandidateSuggestion",
    "EngineCheckResult",
    "InvariantSpec",
    "InvariantViolation",
    "PatchVerificationResult",
    "SecurityPrincipal",
    "StateSnapshot",
    "TransactionPolicy",
    "TransitionSpec",
    "VerificationReport",
    "analyze_source",
    "build_verification_report",
    "StudioHandler",
    "create_studio_server",
    "domain",
    "execute_full_check",
    "run_studio_server",
    "generate_and_verify_patch",
    "invariant",
    "load_toml_invariants",
    "load_toml_transitions",
    "run_verification_engine",
    "transition_invariant",
    "build_sarif_report",
    "to_sarif",
    "resolve_credentials",
    "load_credentials",
    "save_credentials",
    "is_gating_enforced",
    "UPGRADE_URL",
]
