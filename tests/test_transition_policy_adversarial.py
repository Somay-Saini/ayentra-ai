from __future__ import annotations

import ast
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from ayentra.ast_analyzer import analyze_source
from ayentra.contracts import (
    SecurityPrincipal,
    TransactionPolicy,
    TransitionSpec,
    transition_invariant,
)
from ayentra.engine import run_verification_engine
from ayentra.regression import (
    assert_no_silent_403,
    assert_no_silent_field_drops,
    assert_structured_rejection_audit,
)
from ayentra.repair import (
    apply_field_allowlist_and_audit_transform,
    synthesize_field_transition_guard_node,
)
from examples.agent_decision_evaluator import AgentDecisionEvaluator


def test_strict_atomic_unauthorized_compound_payload_rolls_back_and_audited() -> None:
    evaluator = AgentDecisionEvaluator("eval-101")
    pre_state = evaluator.to_dict()
    reviewer = SecurityPrincipal("agent-reviewer-01", "reviewer")

    compound_payload: dict[str, Any] = {
        "evaluation_id": "eval-101",
        "status": "VERIFIED",
        "reviewer_notes": "All automated benchmarks verified cleanly.",
        "reward_usd": 25000,
    }

    with pytest.raises(PermissionError) as exc_info:
        evaluator.update_strict_atomic(compound_payload, reviewer)

    assert "reward_usd" in str(exc_info.value)
    assert reviewer.principal_id in str(exc_info.value)

    # Invariant: strict atomic rollback ensures zero state leakage
    post_state = evaluator.to_dict()
    assert post_state == pre_state
    assert evaluator.status == "PENDING"
    assert evaluator.reviewer_notes == ""
    assert evaluator.reward_usd == 0

    # Non-repudiation: rejection is accompanied by attributed audit record
    assert len(evaluator.audit_log) == 1
    record = evaluator.audit_log[0]
    assert record["event"] == "TRANSACTION_ABORTED_UNAUTHORIZED_MUTATION"
    assert record["principal"] == reviewer.principal_id
    assert record["target_id"] == "eval-101"
    assert record["committed"] is False
    assert record["rejected_fields"] == ["reward_usd"]

    # Regression guardrail assertions pass
    assert_no_silent_403(
        exc_info.value,
        evaluator.audit_log,
        principal=reviewer,
        expected_rejected_fields=["reward_usd"],
    )
    assert_structured_rejection_audit(
        exc_info.value,
        evaluator.audit_log,
        principal=reviewer,
        expected_rejected_fields=["reward_usd"],
    )


def test_strict_atomic_authorized_update_commits_and_audits() -> None:
    evaluator = AgentDecisionEvaluator("eval-102")
    reviewer = SecurityPrincipal("agent-reviewer-02", "reviewer")

    authorized_payload: dict[str, Any] = {
        "evaluation_id": "eval-102",
        "status": "VERIFIED",
        "reviewer_notes": "High quality transition audit.",
    }

    result = evaluator.update_strict_atomic(authorized_payload, reviewer)
    assert result is True

    # State applied
    assert evaluator.status == "VERIFIED"
    assert evaluator.reviewer_notes == "High quality transition audit."
    assert evaluator.reward_usd == 0

    # Audit log verification
    assert len(evaluator.audit_log) == 1
    record = evaluator.audit_log[0]
    assert record["event"] == "TRANSACTION_COMMITTED"
    assert record["principal"] == reviewer.principal_id
    assert record["committed"] is True
    assert record["rejected_fields"] == []

    # Anti-silent-drop guardrail passes
    pre_state = {"status": "PENDING", "reviewer_notes": "", "reward_usd": 0}
    post_state = evaluator.to_dict()
    assert_no_silent_field_drops(
        authorized_payload,
        pre_state,
        post_state,
        evaluator.audit_log,
        principal=reviewer,
        allowed_fields=["evaluation_id", "status", "reviewer_notes"],
    )


def test_selective_drop_preserves_authorized_and_drops_unauthorized_with_audit() -> None:
    evaluator = AgentDecisionEvaluator("eval-103")
    pre_state = evaluator.to_dict()
    reviewer = SecurityPrincipal("agent-reviewer-03", "reviewer")

    compound_payload: dict[str, Any] = {
        "evaluation_id": "eval-103",
        "status": "VERIFIED",
        "reviewer_notes": "Authorized review comments.",
        "reward_usd": 50000,
        "payout_account": "vault_bank_999",
    }

    res = evaluator.update_selective_drop(compound_payload, reviewer)

    # Return contract confirms field separation
    assert res["status"] == "VERIFIED"
    assert res["applied"] == ["evaluation_id", "reviewer_notes", "status"]
    assert res["dropped"] == ["payout_account", "reward_usd"]

    # Authorized fields mutated, unauthorized fields preserved at baseline
    assert evaluator.status == "VERIFIED"
    assert evaluator.reviewer_notes == "Authorized review comments."
    assert evaluator.reward_usd == 0
    assert evaluator.payout_account == ""

    # Non-repudiation audit record dispatched
    assert len(evaluator.audit_log) == 1
    record = evaluator.audit_log[0]
    assert record["event"] == "TRANSACTION_APPLIED_WITH_DROPS"
    assert record["principal"] == reviewer.principal_id
    assert record["applied_fields"] == ["evaluation_id", "reviewer_notes", "status"]
    assert record["rejected_fields"] == ["payout_account", "reward_usd"]
    assert record["committed"] is True

    # Anti-silent-drop guardrail confirms all dropped fields are attributed
    assert_no_silent_field_drops(
        compound_payload,
        pre_state,
        evaluator.to_dict(),
        evaluator.audit_log,
        principal=reviewer,
        allowed_fields=["evaluation_id", "status", "reviewer_notes"],
    )


def test_selective_drop_idempotent_authorized_update() -> None:
    evaluator = AgentDecisionEvaluator("eval-104")
    reviewer = SecurityPrincipal("agent-reviewer-04", "reviewer")

    # Set initial verified state
    evaluator.status = "VERIFIED"
    evaluator.reviewer_notes = "Existing notes"
    pre_state = evaluator.to_dict()

    # Submit same authorized values (idempotent update)
    idempotent_payload = {
        "status": "VERIFIED",
        "reviewer_notes": "Existing notes",
    }

    res = evaluator.update_selective_drop(idempotent_payload, reviewer)
    assert res["status"] == "VERIFIED"
    assert res["applied"] == ["reviewer_notes", "status"]
    assert res["dropped"] == []

    # Guardrail confirms idempotent matches do not trigger false positive
    assert_no_silent_field_drops(
        idempotent_payload,
        pre_state,
        evaluator.to_dict(),
        evaluator.audit_log,
        principal=reviewer,
        allowed_fields=["status", "reviewer_notes"],
    )


def test_regression_guardrail_catches_silent_field_drop_failure() -> None:
    reviewer = SecurityPrincipal("agent-reviewer-05", "reviewer")
    pre_state = {"status": "PENDING", "reward_usd": 0}
    # Buggy mutation: status applied, reward_usd silently ignored without audit
    post_state = {"status": "VERIFIED", "reward_usd": 0}
    payload = {"status": "VERIFIED", "reward_usd": 10000}
    empty_audit_log: list[dict[str, Any]] = []

    with pytest.raises(AssertionError) as exc_info:
        assert_no_silent_field_drops(
            payload,
            pre_state,
            post_state,
            empty_audit_log,
            principal=reviewer,
            allowed_fields=["status"],
        )

    assert "Silent field drop detected" in str(exc_info.value)
    assert "reward_usd" in str(exc_info.value)


def test_regression_guardrail_catches_silent_403_failure() -> None:
    reviewer = SecurityPrincipal("agent-reviewer-06", "reviewer")
    empty_audit_log: list[dict[str, Any]] = []
    opaque_exception = PermissionError("Forbidden")

    with pytest.raises(AssertionError) as exc_info:
        assert_no_silent_403(
            opaque_exception,
            empty_audit_log,
            principal=reviewer,
            expected_rejected_fields=["reward_usd"],
        )

    assert "Silent 403 detected" in str(exc_info.value)


def test_ast_analyzer_detects_mass_assignment(tmp_path: Path) -> None:
    source_code = """
class UnsafeUpdater:
    def update_data(self, payload: dict) -> None:
        for k, v in payload.items():
            setattr(self, k, v)
"""
    target_path = tmp_path / "unsafe_updater.py"
    target_path.write_text(source_code, encoding="utf-8")

    result = analyze_source(target_path)
    suggestions = [s for s in result.suggestions if "mass assignment" in s.rationale.lower()]
    assert len(suggestions) >= 1
    assert "allowlist" in suggestions[0].rationale.lower()


def test_ast_analyzer_detects_split_commit_leak(tmp_path: Path) -> None:
    source_code = """
class UnsafeEvaluator:
    def update(self, payload: dict) -> None:
        self.status = payload["status"]
        if "reward_usd" in payload:
            raise PermissionError("reward_usd not permitted")
"""
    target_path = tmp_path / "unsafe_evaluator.py"
    target_path.write_text(source_code, encoding="utf-8")

    result = analyze_source(target_path)
    suggestions = [s for s in result.suggestions if "split-commit" in s.rationale.lower() or "atomic rollback" in s.rationale.lower()]
    assert len(suggestions) >= 1
    assert "status" in suggestions[0].rationale


def test_repair_synthesizes_field_transition_guard() -> None:
    tree = ast.parse(
        """
def update_decision(self, payload: dict, principal: Any) -> None:
    self.status = payload['status']
"""
    )
    fn_node = tree.body[0]
    assert isinstance(fn_node, ast.FunctionDef)

    guards = synthesize_field_transition_guard_node(
        fn_node,
        policy=TransactionPolicy.STRICT_ATOMIC,
        allowed_fields={"reviewer": ["status", "reviewer_notes"]},
        payload_param="payload",
        principal_param="principal",
    )
    assert len(guards) >= 1

    # Format synthesized AST and verify structure
    unparsed = "\n".join(ast.unparse(g) for g in guards)
    assert "_unauthorized" in unparsed
    assert "PermissionError" in unparsed


def test_concurrency_dirty_read_isolation() -> None:
    evaluator = AgentDecisionEvaluator("eval-concurrent")
    reviewer = SecurityPrincipal("agent-reviewer-concurrent", "reviewer")

    dirty_reads_observed = 0
    stop_event = threading.Event()

    def writer_thread() -> None:
        while not stop_event.is_set():
            # Submit compound payload with unauthorized reward_usd (must rollback)
            try:
                evaluator.update_strict_atomic(
                    {"status": "VERIFIED", "reward_usd": 999999},
                    reviewer,
                )
            except PermissionError:
                pass
            time.sleep(0.001)

    def reader_thread() -> None:
        nonlocal dirty_reads_observed
        while not stop_event.is_set():
            current_status = evaluator.status
            current_reward = evaluator.reward_usd
            # Intermediate dirty read condition: status set to VERIFIED but reward not applied or in rollback
            if current_status == "VERIFIED" and current_reward != 999999:
                dirty_reads_observed += 1
            time.sleep(0.001)

    w = threading.Thread(target=writer_thread, daemon=True)
    r = threading.Thread(target=reader_thread, daemon=True)
    w.start()
    r.start()

    time.sleep(0.08)
    stop_event.set()
    w.join(timeout=1.0)
    r.join(timeout=1.0)

    # Invariant: reader must never witness intermediate dirty state
    assert dirty_reads_observed == 0
    assert evaluator.status == "PENDING"
    assert evaluator.reward_usd == 0


def test_engine_run_verification_on_transition_contract(tmp_path: Path) -> None:
    target_code = """from __future__ import annotations
from dataclasses import dataclass
from ayentra.contracts import transition_invariant, TransactionPolicy, SecurityPrincipal

@transition_invariant(
    "self.status == 'VERIFIED' if 'status' in payload else True",
    policy=TransactionPolicy.STRICT_ATOMIC,
    allowed_fields={"reviewer": ["status", "notes"]},
    description="Verify status transition",
)
class CleanReviewModel:
    def __init__(self) -> None:
        self.status = "PENDING"

    def update_model(self, payload: dict, principal: SecurityPrincipal) -> bool:
        if "status" in payload:
            self.status = str(payload["status"])
        return True
"""
    module_path = tmp_path / "review_model.py"
    module_path.write_text(target_code, encoding="utf-8")

    result = run_verification_engine(module_path, seed_val=42, max_examples=15)
    assert len(result.invariants_checked) >= 1 or len(result.transitions_checked) >= 1
    assert result.duration_ms > 0
