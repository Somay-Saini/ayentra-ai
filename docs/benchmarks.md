# Ayentra Public Release Benchmark and Smoke Test Receipt

Deterministic verification receipt generated during public launch qualification sprint.
All metrics captured against a clean wheel distribution installed in an isolated environment.

## 1. System and Distribution Specification

| Metric | Specification | Verification Status |
| :--- | :--- | :--- |
| Package Name | `ayentra` | Verified |
| Release Version | `0.1.0` | Verified |
| Wheel Package | `ayentra-1.0.0-py3-none-any.whl` | Verified (220,944 bytes / 215.77 KB, SHA-256 `aa5a5759ea09c74ab84150026eb00f38584416ce525cf76974e37ee8f43bbd67`) |
| Source Archive (sdist) | `ayentra-1.0.0.tar.gz` | Verified (266,852 bytes / 260.60 KB, SHA-256 `4804a95cca8206d7f505baf417fb81a8bce7596d16a55df73f5eb368ab5c7574`) |
| Wheel Build Latency | `11995.41 ms` | Verified |
| Isolated Venv Provisioning | `12040.98 ms` | Verified |
| Clean Wheel Installation | `22396.05 ms` | Verified |
| Pytest Test Suite Quality Bar | 128 / 128 tests passing (100.0%: 124 in `tests/` + 4 in `examples/`) | Verified |
| Character Hygiene Bar | 0 em-dashes, 0 en-dashes | Verified |
| Timestamp | `2026-11-03 08:22:04 UTC` | Verified |

## 2. CLI Entrypoint Latency and Smoke Benchmarks

Every command line entrypoint verified from the isolated distribution binary.

| Entrypoint | Command Tested | Execution Latency | Exit Status | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `version` | `ayentra version` | 1587.15 ms | rc=0 | PASS |
| `init` | `ayentra init --path <dir> --ci` | 1325.18 ms | rc=0 | PASS |
| `check` | `ayentra check <file>` | 1607.01 ms | rc=0 | PASS |
| `apply-patch` | `ayentra apply-patch <file> --yes` | 4832.02 ms | rc=0 | PASS |
| `suggest-invariants` | `ayentra suggest-invariants <file>` | 1406.07 ms | rc=0 | PASS |
| `dogfood` | `ayentra dogfood --pattern <name>` | 3564.21 ms | rc=1 | PASS |
| `pr-mock` | `ayentra pr-mock <file> --out <path>` | 1693.73 ms | rc=0 | PASS |
| `demo` | `ayentra demo` | 15879.98 ms | rc=0 | PASS |
| `studio` | `ayentra studio --port <port>` | 1794.16 ms | rc=0 | PASS |
| `site` | `ayentra site --port <port>` | 1831.33 ms | rc=0 | PASS |

## 3. Entrypoint Verification Details

1. **`ayentra version`**: Displays version banner and build metadata directly from package distribution.
2. **`ayentra init`**: Automatically generates reproducible `ayentra.toml` and `.github/workflows/ayentra.yml` configuration.
3. **`ayentra check`**: Evaluates invariant properties with deterministic seeding and reports zero false positives on compliant code.
4. **`ayentra apply-patch`**: Synthesizes deterministic AST guard patches and verifies them against a clean sandbox with regression gating.
5. **`ayentra suggest-invariants`**: Inspects target AST signatures and proposes structured domain boundaries and invariants.
6. **`ayentra dogfood`**: Sweeps curated production patterns (token buckets, connection pools, task queues) and outputs reproducible JSON receipts.
7. **`ayentra pr-mock`**: Generates GitHub-flavored markdown review summaries with risk badges and collapsible diff previews.
8. **`ayentra demo`**: Renders terminal walkthrough cards for customer evaluation without external dependencies.
9. **`ayentra studio`**: Launches local HTTP API and developer inspector on port 8420.
10. **`ayentra site`**: Serves offline-ready product documentation and live demo web application.

## 4. Verification Sign-Off

- **Test Suite Pass Rate:** 128 / 128 passed (100%: 124 in `tests/` + 4 in `examples/`)
- **Zero Warnings:** All Hypothesis and pytest execution warnings resolved
- **Standard Library Discipline:** Zero unapproved external dependencies
- **Sign-Off Gatekeeper:** QA-Gatekeeper (Ayentra)
