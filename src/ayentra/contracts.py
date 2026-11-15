from __future__ import annotations

import inspect
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable


class TransactionPolicy(str, Enum):
    STRICT_ATOMIC = "strict_atomic"
    SELECTIVE_DROP = "selective_drop"


@dataclass
class SecurityPrincipal:
    principal_id: str
    role: str


class StateSnapshot:
    """Read-only wrapper around a state snapshot dictionary allowing attribute and dict access."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = dict(data)

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"StateSnapshot has no attribute '{name}'")

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)

    def __repr__(self) -> str:
        return f"StateSnapshot({self._data!r})"


@dataclass(frozen=True)
class InvariantSpec:
    expression: str
    target_name: str
    kind: str  # "class" or "function"
    lineno: int
    filepath: str
    description: str = ""
    check_concurrency: bool = False
    domain_bounds: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TransitionSpec:
    expression: str
    target_name: str
    kind: str  # "class" or "function"
    lineno: int
    filepath: str
    policy: TransactionPolicy = TransactionPolicy.STRICT_ATOMIC
    allowed_fields: dict[str, list[str]] = field(default_factory=dict)
    description: str = ""
    domain_bounds: dict[str, Any] = field(default_factory=dict)


def invariant(
    expression: str,
    *,
    description: str = "",
    check_concurrency: bool = False,
) -> Callable[[Any], Any]:
    """Attach an explicit behavioral invariant to a class or function."""
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("Invariant expression must be a non-empty string.")

    def decorator(obj: Any) -> Any:
        try:
            filepath = inspect.getsourcefile(obj) or "<unknown>"
            _, lineno = inspect.getsourcelines(obj)
        except (OSError, TypeError):
            filepath = "<unknown>"
            lineno = 1

        kind = "class" if inspect.isclass(obj) else "function"
        existing: list[InvariantSpec] = list(getattr(obj, "__ayentra_invariants__", []))
        bounds: dict[str, Any] = dict(getattr(obj, "__ayentra_domain__", {}))
        spec = InvariantSpec(
            expression=expression.strip(),
            target_name=obj.__qualname__,
            kind=kind,
            lineno=lineno,
            filepath=filepath,
            description=description,
            check_concurrency=check_concurrency,
            domain_bounds=bounds,
        )
        existing.append(spec)
        setattr(obj, "__ayentra_invariants__", existing)
        return obj

    return decorator


def transition_invariant(
    expression: str,
    *,
    policy: TransactionPolicy | str = TransactionPolicy.STRICT_ATOMIC,
    allowed_fields: dict[str, list[str]] | None = None,
    description: str = "",
) -> Callable[[Any], Any]:
    """Attach an explicit state transition invariant with transaction policy semantics."""
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("Transition invariant expression must be a non-empty string.")

    if isinstance(policy, str):
        try:
            resolved_policy = TransactionPolicy(policy)
        except ValueError:
            raise ValueError(f"Unknown transaction policy: {policy}. Must be 'strict_atomic' or 'selective_drop'.")
    elif isinstance(policy, TransactionPolicy):
        resolved_policy = policy
    else:
        raise ValueError("Policy must be a TransactionPolicy or valid policy string.")

    norm_allowed_fields: dict[str, list[str]] = {}
    if allowed_fields is not None:
        if isinstance(allowed_fields, dict):
            for r_k, r_v in allowed_fields.items():
                if isinstance(r_v, (list, tuple, set)):
                    norm_allowed_fields[str(r_k)] = [str(f) for f in r_v]
                else:
                    norm_allowed_fields[str(r_k)] = [str(r_v)]

    def decorator(obj: Any) -> Any:
        try:
            filepath = inspect.getsourcefile(obj) or "<unknown>"
            _, lineno = inspect.getsourcelines(obj)
        except (OSError, TypeError):
            filepath = "<unknown>"
            lineno = 1

        kind = "class" if inspect.isclass(obj) else "function"
        existing: list[TransitionSpec] = list(getattr(obj, "__ayentra_transitions__", []))
        bounds: dict[str, Any] = dict(getattr(obj, "__ayentra_domain__", {}))
        spec = TransitionSpec(
            expression=expression.strip(),
            target_name=obj.__qualname__,
            kind=kind,
            lineno=lineno,
            filepath=filepath,
            policy=resolved_policy,
            allowed_fields=norm_allowed_fields,
            description=description,
            domain_bounds=bounds,
        )
        existing.append(spec)
        setattr(obj, "__ayentra_transitions__", existing)
        return obj

    return decorator


def domain(**bounds: Any) -> Callable[[Any], Any]:
    """Declare explicit parameter domain bounds for property-based testing."""

    def decorator(obj: Any) -> Any:
        current = dict(getattr(obj, "__ayentra_domain__", {}))
        current.update(bounds)
        setattr(obj, "__ayentra_domain__", current)
        if hasattr(obj, "__ayentra_invariants__"):
            updated = [
                InvariantSpec(
                    expression=inv.expression,
                    target_name=inv.target_name,
                    kind=inv.kind,
                    lineno=inv.lineno,
                    filepath=inv.filepath,
                    description=inv.description,
                    check_concurrency=inv.check_concurrency,
                    domain_bounds=current,
                )
                for inv in getattr(obj, "__ayentra_invariants__")
            ]
            setattr(obj, "__ayentra_invariants__", updated)
        if hasattr(obj, "__ayentra_transitions__"):
            updated_trans = [
                TransitionSpec(
                    expression=t.expression,
                    target_name=t.target_name,
                    kind=t.kind,
                    lineno=t.lineno,
                    filepath=t.filepath,
                    policy=t.policy,
                    allowed_fields=t.allowed_fields,
                    description=t.description,
                    domain_bounds=current,
                )
                for t in getattr(obj, "__ayentra_transitions__")
            ]
            setattr(obj, "__ayentra_transitions__", updated_trans)
        return obj

    return decorator


def _find_toml_file(target_filepath: str, toml_path: Path | None = None) -> Path | None:
    if toml_path is not None and toml_path.is_file():
        return toml_path
    t_path = Path(target_filepath).resolve()
    for parent in [t_path.parent, *t_path.parents]:
        cand = parent / "ayentra.toml"
        if cand.is_file():
            return cand
        cand_pyproject = parent / "pyproject.toml"
        if cand_pyproject.is_file() and cand.is_file():
            return cand
    return None


def load_toml_invariants(toml_path: Path, target_filepath: str) -> list[InvariantSpec]:
    """Load explicit invariants defined in an ayentra.toml specification file."""
    resolved_toml = _find_toml_file(target_filepath, toml_path)
    if not resolved_toml:
        return []
    data = tomllib.loads(resolved_toml.read_text(encoding="utf-8"))
    specs: list[InvariantSpec] = []
    for entry in data.get("invariants", []):
        if not isinstance(entry, dict):
            continue
        expr = entry.get("expression")
        target = entry.get("target")
        if not expr or not target or not isinstance(expr, str) or not isinstance(target, str):
            continue
        file_match = str(entry.get("file", "")).strip()
        if file_match and Path(file_match).name != Path(target_filepath).name:
            continue
        specs.append(
            InvariantSpec(
                expression=expr.strip(),
                target_name=target.strip(),
                kind=str(entry.get("kind", "function")),
                lineno=int(entry.get("lineno", 1)),
                filepath=target_filepath,
                description=str(entry.get("description", "")),
                check_concurrency=bool(entry.get("check_concurrency", False)),
                domain_bounds=dict(entry.get("domain", {})),
            )
        )
    return specs


def load_toml_transitions(toml_path: Path, target_filepath: str) -> list[TransitionSpec]:
    """Load explicit transition invariants defined in an ayentra.toml specification file."""
    resolved_toml = _find_toml_file(target_filepath, toml_path)
    if not resolved_toml:
        return []
    data = tomllib.loads(resolved_toml.read_text(encoding="utf-8"))
    transitions: list[TransitionSpec] = []
    for entry in data.get("transitions", []):
        if not isinstance(entry, dict):
            continue
        expr = entry.get("expression")
        target = entry.get("target")
        if not expr or not target or not isinstance(expr, str) or not isinstance(target, str):
            continue
        file_match = str(entry.get("file", "")).strip()
        if file_match and Path(file_match).name != Path(target_filepath).name:
            continue
        policy_str = str(entry.get("policy", "strict_atomic"))
        try:
            policy = TransactionPolicy(policy_str)
        except ValueError:
            policy = TransactionPolicy.STRICT_ATOMIC
        allowed = entry.get("allowed_fields", {})
        norm_allowed = {}
        if isinstance(allowed, dict):
            for k, v in allowed.items():
                if isinstance(v, (list, tuple, set)):
                    norm_allowed[str(k)] = [str(x) for x in v]
                else:
                    norm_allowed[str(k)] = [str(v)]
        transitions.append(
            TransitionSpec(
                expression=expr.strip(),
                target_name=target.strip(),
                kind=str(entry.get("kind", "class")),
                lineno=int(entry.get("lineno", 1)),
                filepath=target_filepath,
                policy=policy,
                allowed_fields=norm_allowed,
                description=str(entry.get("description", "")),
                domain_bounds=dict(entry.get("domain", {})),
            )
        )
    return transitions
