from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ayentra.contracts import (
    SecurityPrincipal,
    TransactionPolicy,
    domain,
    invariant,
    transition_invariant,
)


@dataclass
class AuditRecord:
    event: str
    principal_id: str
    target_id: str
    applied_fields: list[str]
    rejected_fields: list[str]
    policy: str
    committed: bool


@invariant(
    "self.reward_usd >= 0",
    description="Reward funds must be non-negative",
)
class AgentDecisionEvaluator:
    """Evaluates autonomous agent review decisions with field-level access control."""

    ALLOWED_FIELDS_BY_ROLE: dict[str, set[str]] = {
        "reviewer": {"evaluation_id", "status", "reviewer_notes"},
        "admin": {"evaluation_id", "status", "reviewer_notes", "reward_usd", "payout_account"},
        "auditor": {"evaluation_id", "reviewer_notes"},
    }

    def __init__(self, evaluation_id: str = "eval-default") -> None:
        self.evaluation_id: str = evaluation_id
        self.status: str = "PENDING"
        self.reviewer_notes: str = ""
        self.reward_usd: int = 0
        self.payout_account: str = ""
        self._audit_records: list[AuditRecord] = []

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        return [
            {
                "event": r.event,
                "principal": r.principal_id,
                "target_id": r.target_id,
                "applied_fields": list(r.applied_fields),
                "rejected_fields": list(r.rejected_fields),
                "policy": r.policy,
                "committed": r.committed,
            }
            for r in self._audit_records
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "status": self.status,
            "reviewer_notes": self.reviewer_notes,
            "reward_usd": self.reward_usd,
            "payout_account": self.payout_account,
        }

    @domain(
        payload={"__known_fields__": ["status", "reviewer_notes", "reward_usd"]},
        principal={"__roles__": ["reviewer", "admin", "auditor"]},
    )
    @transition_invariant(
        "self.reward_usd == old.reward_usd if principal.role != 'admin' else True",
        policy=TransactionPolicy.STRICT_ATOMIC,
        allowed_fields={
            "reviewer": ["evaluation_id", "status", "reviewer_notes"],
            "admin": ["evaluation_id", "status", "reviewer_notes", "reward_usd", "payout_account"],
            "auditor": ["evaluation_id", "reviewer_notes"],
        },
        description="Reviewers cannot alter reward funds under strict atomic policy",
    )
    def update_strict_atomic(
        self,
        payload: dict[str, Any],
        principal: SecurityPrincipal,
    ) -> bool:
        """Applies compound mutations under strict atomic rollback policy."""
        allowed = self.ALLOWED_FIELDS_BY_ROLE.get(principal.role, set())
        attempted = set(payload.keys())
        unauthorized = attempted - allowed

        if unauthorized:
            self._audit_records.append(
                AuditRecord(
                    event="TRANSACTION_ABORTED_UNAUTHORIZED_MUTATION",
                    principal_id=principal.principal_id,
                    target_id=self.evaluation_id,
                    applied_fields=[],
                    rejected_fields=sorted(unauthorized),
                    policy="strict_atomic",
                    committed=False,
                )
            )
            raise PermissionError(
                f"Principal '{principal.principal_id}' unauthorized to mutate fields: {sorted(unauthorized)}"
            )

        # Stage and commit mutations atomically
        if "status" in payload:
            self.status = str(payload["status"])
        if "reviewer_notes" in payload:
            self.reviewer_notes = str(payload["reviewer_notes"])
        if "reward_usd" in payload:
            val = int(payload["reward_usd"])
            if val < 0:
                raise ValueError("reward_usd must be non-negative")
            self.reward_usd = val
        if "payout_account" in payload:
            self.payout_account = str(payload["payout_account"])

        self._audit_records.append(
            AuditRecord(
                event="TRANSACTION_COMMITTED",
                principal_id=principal.principal_id,
                target_id=self.evaluation_id,
                applied_fields=sorted(attempted),
                rejected_fields=[],
                policy="strict_atomic",
                committed=True,
            )
        )
        return True

    @domain(
        payload={"__known_fields__": ["status", "reviewer_notes", "reward_usd"]},
        principal={"__roles__": ["reviewer", "admin", "auditor"]},
    )
    @transition_invariant(
        "self.reward_usd == old.reward_usd if principal.role != 'admin' else True",
        policy=TransactionPolicy.SELECTIVE_DROP,
        allowed_fields={
            "reviewer": ["evaluation_id", "status", "reviewer_notes"],
            "admin": ["evaluation_id", "status", "reviewer_notes", "reward_usd", "payout_account"],
            "auditor": ["evaluation_id", "reviewer_notes"],
        },
        description="Selective drop preserves authorized fields and drops unauthorized",
    )
    def update_selective_drop(
        self,
        payload: dict[str, Any],
        principal: SecurityPrincipal,
    ) -> dict[str, Any]:
        """Applies authorized fields and drops unauthorized mutations with non-repudiation audit."""
        allowed = self.ALLOWED_FIELDS_BY_ROLE.get(principal.role, set())
        attempted = set(payload.keys())
        unauthorized = attempted - allowed
        authorized = attempted & allowed

        # Apply authorized modifications only
        if "status" in authorized:
            self.status = str(payload["status"])
        if "reviewer_notes" in authorized:
            self.reviewer_notes = str(payload["reviewer_notes"])
        if "reward_usd" in authorized:
            val = int(payload["reward_usd"])
            if val < 0:
                raise ValueError("reward_usd must be non-negative")
            self.reward_usd = val
        if "payout_account" in authorized:
            self.payout_account = str(payload["payout_account"])

        event_name = "TRANSACTION_APPLIED_WITH_DROPS" if unauthorized else "TRANSACTION_APPLIED"
        self._audit_records.append(
            AuditRecord(
                event=event_name,
                principal_id=principal.principal_id,
                target_id=self.evaluation_id,
                applied_fields=sorted(authorized),
                rejected_fields=sorted(unauthorized),
                policy="selective_drop",
                committed=True,
            )
        )

        return {
            "applied": sorted(authorized),
            "dropped": sorted(unauthorized),
            "status": self.status,
        }
