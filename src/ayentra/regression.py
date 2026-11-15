from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RegressionRunResult:
    passed: bool
    passed_count: int
    failed_count: int
    duration_ms: float
    output_summary: str
    audit_guardrails_passed: bool = True
    guardrail_details: dict[str, Any] = field(default_factory=dict)


def run_pytest_suite(
    working_dir: str | Path,
    test_target: str | Path | None = None,
) -> RegressionRunResult:
    t0 = time.perf_counter()
    cwd = Path(working_dir).resolve()

    target = str(test_target) if test_target is not None else ("examples" if (cwd / "examples").is_dir() else ".")
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        target,
        "-q",
        "--tb=short",
        "--no-header",
    ]
    if Path(cwd, "src", "ayentra").exists():
        cmd.append("--ignore=tests")

    env = dict(os.environ)
    src_dir = str(Path(__file__).resolve().parents[1])
    existing_pp = env.get("PYTHONPATH", "")
    parts = [str(cwd), src_dir]
    if existing_pp:
        parts.append(existing_pp)
    env["PYTHONPATH"] = os.pathsep.join(parts)

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return RegressionRunResult(
            passed=False,
            passed_count=0,
            failed_count=1,
            duration_ms=30000.0,
            output_summary="Pytest suite timed out after 30 seconds.",
        )
    duration_ms = (time.perf_counter() - t0) * 1000.0
    stdout = (proc.stdout or "") + "\n" + (proc.stderr or "")

    passed_match = re.search(r"(\d+)\s+passed", stdout)
    failed_match = re.search(r"(\d+)\s+(?:failed|error)", stdout)
    passed_count = int(passed_match.group(1)) if passed_match else 0
    failed_count = int(failed_match.group(1)) if failed_match else 0

    if proc.returncode == 5:
        # pytest exit code 5: no tests collected
        return RegressionRunResult(
            passed=True,
            passed_count=0,
            failed_count=0,
            duration_ms=duration_ms,
            output_summary="No existing pytest tests collected (0 failed)",
        )

    ok = proc.returncode == 0 and failed_count == 0
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    summary = lines[-1] if lines else ("PASSED" if ok else "FAILED")
    return RegressionRunResult(
        passed=ok,
        passed_count=passed_count,
        failed_count=failed_count,
        duration_ms=duration_ms,
        output_summary=summary,
    )


def assert_no_silent_field_drops(
    payload: dict[str, Any],
    pre_state: dict[str, Any] | Any,
    post_state: dict[str, Any] | Any,
    audit_log: list[dict[str, Any]] | Any,
    *,
    principal: Any = None,
    allowed_fields: list[str] | set[str] | None = None,
) -> None:
    """Ensure that no fields from an update payload were silently unapplied or dropped without an attributed audit record.

    Handles idempotent authorized fields cleanly where the payload value matches
    pre-state, only flagging fields that were omitted or unapplied from post-state
    and lack a corresponding non-repudiation audit record.
    """
    if hasattr(pre_state, "to_dict") and callable(pre_state.to_dict):
        pre_dict = dict(pre_state.to_dict())
    elif isinstance(pre_state, dict):
        pre_dict = dict(pre_state)
    elif hasattr(pre_state, "__dict__"):
        pre_dict = {k: v for k, v in pre_state.__dict__.items() if not k.startswith("_")}
    else:
        pre_dict = {}

    if hasattr(post_state, "to_dict") and callable(post_state.to_dict):
        post_dict = dict(post_state.to_dict())
    elif isinstance(post_state, dict):
        post_dict = dict(post_state)
    elif hasattr(post_state, "__dict__"):
        post_dict = {k: v for k, v in post_state.__dict__.items() if not k.startswith("_")}
    else:
        post_dict = {}

    if isinstance(audit_log, list):
        audit_entries = audit_log
    elif hasattr(audit_log, "audit_log") and isinstance(audit_log.audit_log, list):
        audit_entries = audit_log.audit_log
    elif hasattr(audit_log, "_audit_log") and isinstance(audit_log._audit_log, list):
        audit_entries = audit_log._audit_log
    else:
        audit_entries = []

    p_id = getattr(principal, "principal_id", str(principal)) if principal is not None else None
    p_role = getattr(principal, "role", None) if principal is not None else None
    allowed_set = set(allowed_fields) if allowed_fields is not None else None

    silent_drops: list[str] = []

    for k, attempted_val in payload.items():
        # Case 1: Value is reflected in post_dict
        if k in post_dict and post_dict[k] == attempted_val:
            continue

        # Case 2: Authorized idempotent update where payload matched pre-state
        if (
            allowed_set is not None
            and k in allowed_set
            and k in pre_dict
            and pre_dict[k] == attempted_val
        ):
            continue

        if allowed_set is None and k in pre_dict and pre_dict[k] == attempted_val and k in post_dict:
            continue

        # Case 3: The field was unapplied or dropped from post_dict.
        # Check if an audit record attributes this dropped/rejected field.
        audited = False
        for entry in audit_entries:
            if not isinstance(entry, dict):
                continue
            rej = entry.get("rejected_fields", [])
            if isinstance(rej, (list, tuple, set)):
                rej_set = set(rej)
            else:
                rej_set = {str(rej)}

            if k in rej_set or k in entry.get("rejected_delta", {}):
                # Verify principal attribution if provided
                if p_id is not None:
                    entry_p = entry.get("principal")
                    entry_r = entry.get("role")
                    if entry_p in (p_id, p_role) or entry_r in (p_id, p_role):
                        audited = True
                        break
                else:
                    audited = True
                    break

        if not audited:
            silent_drops.append(k)

    if silent_drops:
        raise AssertionError(
            f"Silent field drop detected: Field(s) {sorted(silent_drops)} from update payload were dropped or unapplied without an attributed audit record."
        )


def assert_structured_rejection_audit(
    exception_or_response: Exception | dict[str, Any] | Any,
    audit_log: list[dict[str, Any]] | Any,
    *,
    principal: Any = None,
    expected_rejected_fields: list[str] | set[str] | None = None,
) -> None:
    """Ensure that an authorization rejection is structured and accompanied by an attributed security audit record.

    Verifies non-repudiation: rejection reasons must not be opaque silent 403s
    and must identify the acting principal and rejected field delta.
    """
    # 1. Verify structured diagnostic detail in exception or response
    if isinstance(exception_or_response, BaseException):
        err_msg = str(exception_or_response)
        if not err_msg.strip():
            raise AssertionError("Silent 403 detected: Authorization exception has empty error message.")
        if expected_rejected_fields:
            missing_in_msg = [f for f in expected_rejected_fields if f not in err_msg]
            if missing_in_msg and not hasattr(exception_or_response, "rejected_fields"):
                raise AssertionError(
                    f"Silent 403 detected: Exception message does not mention rejected field(s): {missing_in_msg}."
                )
    elif isinstance(exception_or_response, dict):
        if not any(k in exception_or_response for k in ("error", "message", "rejected_fields", "detail")):
            raise AssertionError("Silent 403 detected: Rejection response lacks structured error details.")

    # 2. Verify audit trail contains corresponding entry
    if isinstance(audit_log, list):
        audit_entries = audit_log
    elif hasattr(audit_log, "audit_log") and isinstance(audit_log.audit_log, list):
        audit_entries = audit_log.audit_log
    elif hasattr(audit_log, "_audit_log") and isinstance(audit_log._audit_log, list):
        audit_entries = audit_log._audit_log
    else:
        audit_entries = []

    if not audit_entries:
        raise AssertionError("Silent 403 detected: Operation was rejected but no audit record was dispatched.")

    p_id = getattr(principal, "principal_id", str(principal)) if principal is not None else None
    p_role = getattr(principal, "role", None) if principal is not None else None

    matching = False
    for entry in audit_entries:
        if not isinstance(entry, dict):
            continue
        rej = entry.get("rejected_fields", [])
        if isinstance(rej, (list, tuple, set)):
            rej_set = set(rej)
        else:
            rej_set = {str(rej)}

        if p_id is not None:
            entry_p = entry.get("principal")
            entry_r = entry.get("role")
            if entry_p not in (p_id, p_role) and entry_r not in (p_id, p_role):
                continue

        if expected_rejected_fields:
            if not any(f in rej_set for f in expected_rejected_fields):
                continue

        matching = True
        break

    if not matching:
        raise AssertionError(
            f"Silent 403 detected: Audit log lacks an entry attributing rejected fields {expected_rejected_fields} to principal '{p_id}'."
        )


assert_no_silent_403 = assert_structured_rejection_audit

__all__ = [
    "RegressionRunResult",
    "run_pytest_suite",
    "assert_no_silent_field_drops",
    "assert_no_silent_403",
    "assert_structured_rejection_audit",
]

