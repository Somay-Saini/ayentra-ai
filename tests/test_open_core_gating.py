from __future__ import annotations

import json
from pathlib import Path
import pytest
from rich.console import Console

from ayentra.cli import build_parser, main
from ayentra.cloud import (
    DEFAULT_CLOUD_URL,
    UPGRADE_URL,
    get_credentials_path,
    is_gating_enforced,
    load_credentials,
    resolve_credentials,
    save_credentials,
    verify_receipt,
)


def test_zero_public_version_numbers_law(capsys: pytest.CaptureFixture[str]) -> None:
    # 1. Subcommand
    rc_ver = main(["version"])
    assert rc_ver == 0
    captured_ver = capsys.readouterr().out
    assert "ayentra" in captured_ver
    assert "1.0.0" not in captured_ver
    assert "v1.0.0" not in captured_ver
    assert "v0.1.0" not in captured_ver
    assert chr(0x2014) not in captured_ver and chr(0x2013) not in captured_ver

    # 2. Flag --version
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured_flag = capsys.readouterr()
    flag_out = captured_flag.out or captured_flag.err
    assert "ayentra" in flag_out
    assert "1.0.0" not in flag_out
    assert "v1.0.0" not in flag_out
    assert "v0.1.0" not in flag_out
    assert chr(0x2014) not in flag_out and chr(0x2013) not in flag_out


def test_open_core_gating_directory_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AYENTRA_ENFORCE_GATING", "1")
    monkeypatch.delenv("AYENTRA_API_KEY", raising=False)
    monkeypatch.delenv("AYENTRA_LICENSE_KEY", raising=False)

    fake_creds = tmp_path / "no_creds.json"
    monkeypatch.setattr("ayentra.cloud.get_credentials_path", lambda: fake_creds)

    sub_dir = tmp_path / "repo"
    sub_dir.mkdir()
    (sub_dir / "target.py").write_text("def foo(): pass\n", encoding="utf-8")

    rc = main(["check", str(sub_dir)])
    assert rc == 3
    out = capsys.readouterr().out
    assert "License Required (Ayentra Team)" in out
    assert UPGRADE_URL in out
    assert chr(0x2014) not in out and chr(0x2013) not in out


def test_open_core_gating_sarif_and_pr_comment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AYENTRA_ENFORCE_GATING", "1")
    monkeypatch.delenv("AYENTRA_API_KEY", raising=False)
    monkeypatch.delenv("AYENTRA_LICENSE_KEY", raising=False)
    fake_creds = tmp_path / "no_creds.json"
    monkeypatch.setattr("ayentra.cloud.get_credentials_path", lambda: fake_creds)

    single_file = tmp_path / "mod.py"
    single_file.write_text("def bar(): pass\n", encoding="utf-8")

    # SARIF flag
    rc_sarif = main(["check", str(single_file), "--sarif", str(tmp_path / "out.sarif")])
    assert rc_sarif == 3
    out_sarif = capsys.readouterr().out
    assert "License Required (Ayentra Team)" in out_sarif
    assert "OASIS SARIF 2.1.0" in out_sarif

    # PR comment flag
    rc_pr = main(["check", str(single_file), "--pr-comment", str(tmp_path / "comment.md")])
    assert rc_pr == 3
    out_pr = capsys.readouterr().out
    assert "License Required (Ayentra Team)" in out_pr
    assert "PR review bot comments" in out_pr


def test_open_core_gating_auto_repair_apply_and_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AYENTRA_ENFORCE_GATING", "1")
    monkeypatch.delenv("AYENTRA_API_KEY", raising=False)
    monkeypatch.delenv("AYENTRA_LICENSE_KEY", raising=False)
    fake_creds = tmp_path / "no_creds.json"
    monkeypatch.setattr("ayentra.cloud.get_credentials_path", lambda: fake_creds)

    f = tmp_path / "calc.py"
    f.write_text("def divide(a: int, b: int) -> int:\n    return a // b\n", encoding="utf-8")

    # apply-patch locked without paid key
    rc_apply = main(["apply-patch", str(f)])
    assert rc_apply == 3
    out_apply = capsys.readouterr().out
    assert "License Required (Ayentra Scale)" in out_apply
    assert "3-Gate AST Auto-Repair Synthesizer" in out_apply

    # verify-patch without --candidate-file locked
    rc_ver = main(["verify-patch", str(f)])
    assert rc_ver == 3
    out_ver = capsys.readouterr().out
    assert "License Required (Ayentra Scale)" in out_ver


def test_free_open_core_single_file_offline_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AYENTRA_ENFORCE_GATING", "1")
    monkeypatch.delenv("AYENTRA_API_KEY", raising=False)
    monkeypatch.delenv("AYENTRA_LICENSE_KEY", raising=False)
    fake_creds = tmp_path / "no_creds.json"
    monkeypatch.setattr("ayentra.cloud.get_credentials_path", lambda: fake_creds)

    clean_file = tmp_path / "safe_math.py"
    clean_file.write_text(
        "from __future__ import annotations\n"
        "from ayentra.contracts import invariant, domain\n\n"
        "@invariant('result >= 0')\n"
        "@domain(x='int:0..100')\n"
        "def abs_val(x: int) -> int:\n"
        "    return abs(x)\n",
        encoding="utf-8",
    )

    rc = main(["check", str(clean_file), "--seed", "42", "--max-examples", "50"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS" in out or "All explicit invariants passed" in out or "ALL EXPLICIT INVARIANTS PASSED" in out


def test_auth_login_status_and_credits_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    test_cred_path = tmp_path / "creds.json"
    monkeypatch.setattr("ayentra.cloud.get_credentials_path", lambda: test_cred_path)

    # 1. Status unauthenticated
    monkeypatch.delenv("AYENTRA_API_KEY", raising=False)
    monkeypatch.delenv("AYENTRA_LICENSE_KEY", raising=False)
    rc_stat = main(["auth", "status"])
    assert rc_stat == 0
    out_stat = capsys.readouterr().out
    assert "Developer (Open-Core Free)" in out_stat

    # 2. Login with key
    rc_login = main(["auth", "login", "--key", "ay_live_abcdef1234567890"])
    assert rc_login == 0
    assert test_cred_path.is_file()
    saved = json.loads(test_cred_path.read_text(encoding="utf-8"))
    assert saved["api_key"] == "ay_live_abcdef1234567890"

    # 3. Credits CLI
    monkeypatch.setenv("AYENTRA_MOCK_CLOUD", "1")
    rc_credits = main(["credits"])
    assert rc_credits == 0
    out_cred = capsys.readouterr().out
    assert "Credits" in out_cred
    assert chr(0x2014) not in out_cred and chr(0x2013) not in out_cred


def test_verify_receipt_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt_file = tmp_path / "ayentra-receipt.json"
    receipt_file.write_text(
        json.dumps({
            "target": "ledger.py",
            "passed_invariants_count": 2,
            "failed_invariants_count": 0,
            "receipt_signature": "mock_ed25519_signature_test",
            "key_id": "ayentra-ed25519-2026-11",
        }),
        encoding="utf-8",
    )

    rc = main(["verify-receipt", str(receipt_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert chr(0x2014) not in out and chr(0x2013) not in out
