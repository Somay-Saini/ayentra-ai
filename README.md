# Ayentra: Invariant-Aware Verification Gate

Ayentra checks whether backend code violates explicitly defined behavioral invariants, finds minimal reproducible counterexamples using property-based shrinking and deterministic thread interleaving, and verifies candidate fixes in an isolated sandbox against both the invariant and your existing regression suite before merge (Python reference engine live, Go and TypeScript adapters in preview, Rust on roadmap).

[![Live Showcase](https://img.shields.io/badge/Live_Showcase-ayentra--ai.vercel.app-0F766E?style=flat-square)](https://ayentra-ai.vercel.app/)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Somay--Saini%2Fayentra--ai-1E232A?style=flat-square)](https://github.com/Somay-Saini/ayentra-ai)
[![Security Policy](https://img.shields.io/badge/Security_Policy-SECURITY.md-166534?style=flat-square)](https://github.com/Somay-Saini/ayentra-ai/blob/main/SECURITY.md)

- **Live Public Showcase**: [https://ayentra-ai.vercel.app/](https://ayentra-ai.vercel.app/)
- **Interactive Verification Studio**: [Live Invariant Inspector & PR Bot Simulator](https://ayentra-ai.vercel.app/#demo)
- **GitHub Repository**: [https://github.com/Somay-Saini/ayentra-ai](https://github.com/Somay-Saini/ayentra-ai)
- **Pricing & Cloud Control Plane Portal**: [https://ayentra-ai.vercel.app/#pricing](https://ayentra-ai.vercel.app/#pricing)

## Design Principles & Technical Boundaries

1. **Explicit Invariants First**: AST analysis cannot guess intended business rules. Invariants are declared explicitly via `@invariant(...)` decorators or workspace `ayentra.toml` contracts. Structural hints extracted by the AST analyzer are always labeled `Candidate Suggestion (Requires Developer Approval)` and never enforced automatically.
2. **Exact Verification Reporting, Strategy Synthesis & Async Coroutine Support**: Ayentra synthesizes property strategies from Python type annotations (including primitives, `decimal.Decimal`, `datetime.date`, `datetime.datetime`, `Optional`/`Union`, `list`, `dict`, `tuple`, `set`, `frozenset`, `Literal`, `Enum`, and nested `@dataclass` types), executes both synchronous callables and `async def` coroutine functions and methods (including AST candidate invariant extraction and sandbox guard repair for `async def`, `Decimal` zero-division, and date/datetime order bounds), and reports the exact verification method (`Property-Based Shrinking via Hypothesis` or `Deterministic Thread Interleaving Check`), the exact number of cases or schedules evaluated, the tested input domain bounds, and the deterministic `--seed`.
3. **Minimal Reproducible Counterexamples & Concurrency Interleaving**: When an invariant fails, Ayentra shrinks the failing input vector or concurrent schedule to its smallest reproducible form. For `@invariant(..., check_concurrency=True)` class invariants, Ayentra explores barrier-synchronized thread schedules with line-level preemption (`sys.settrace`) across single-argument, multi-argument, and cross-method calls (e.g., concurrent `deposit`/`withdraw` or `reserve`/`release` pairs) to expose TOCTOU race conditions.
4. **Non-Destructive Sandbox Patch Verification**: Ayentra never overwrites source files silently. It synthesizes a candidate unified diff, applies it inside an isolated temporary directory copy, and runs three checks:
   - Replay of the exact failing counterexample
   - Full property-based and concurrency invariant sweep
   - The project's existing `pytest` regression suite
5. **Deterministic Execution Receipts**: Outputs a `VerificationReport` JSON receipt containing the SHA-256 digest of the source file, seed, domain bounds, pass/fail counts, and actual measured execution time in milliseconds.

## CLI Reference

### `ayentra check <target>`

Checks a Python module or directory (`ayentra check <dir/>`). In Open-Core Free mode, `ayentra check <file.py>` runs offline on single files (up to 120 examples). Multi-file repository scans (`ayentra check <dir/>`), `--sarif`, and `--pr-comment` connect to the Ayentra Cloud Control Plane (`AYENTRA_API_KEY`).

```bash
# Check a single module offline with a deterministic seed
ayentra check examples/scheduler_race.py --seed 42

# Check an entire directory of modules and write a JSON receipt
ayentra check examples/ --seed 42 --json-out report.json
```

### `ayentra apply-patch <target> [--yes]`

Synthesizes a candidate repair for a failing target, runs the 3-stage sandbox verification gate (counterexample replay, property-based/concurrency sweep, and `pytest` regression suite), and prints the unified diff. By default, `apply-patch` runs in non-destructive preview mode. Pass `--yes` to write the patch to disk only after all three sandbox stages pass (`VERIFIED CANDIDATE FIX`).

```bash
# Preview the verified unified diff without modifying the file
ayentra apply-patch examples/inventory_ledger.py --seed 42

# Write the patch to disk if and only if all 3 sandbox checks pass
ayentra apply-patch examples/inventory_ledger.py --seed 42 --yes
```

### `ayentra suggest-invariants <target>`

Analyzes the module AST and outputs candidate invariant expressions labeled `Candidate Suggestion (Requires Developer Approval)`.

```bash
ayentra suggest-invariants examples/inventory_ledger.py
```

### `ayentra verify-patch <target> [--candidate-file <path>]`

Verifies either a user-supplied candidate file (`--candidate-file`) or a synthesized patch inside an isolated sandbox copy without modifying the target file.

### `ayentra auth login` & `ayentra credits`

Authenticates with the Ayentra Cloud Control Plane using your API key or license key and displays active tier entitlements and remaining CI credits.

```bash
ayentra auth login --key <YOUR_KEY>
ayentra credits
```

### `ayentra studio`

Launches the local browser verification inspector in the Soft Neutral Light theme (`#F6F5F2` background, `#FCFCFA` surface, `#FFFFFF` panels, `#1E232A` text).

```bash
ayentra studio --port 8420
```

### `ayentra init [--ci] [--path <dir>]`

Scaffolds `ayentra.toml` configuration and optional `.github/workflows/ayentra.yml` for GitHub Actions CI.

```bash
# Initialize local configuration and GitHub Actions CI workflow
ayentra init --ci
```

### `ayentra pr-mock <target> [--pr-comment <path.md>] [--sarif <path.sarif>]`

Generates a structured GitHub pull request review comment with plain-English risk categorization, minimal shrunk counterexample, collapsible unified diff, and 1-click merge command.

```bash
# Generate simulated PR review comment for customer pilot ledger
ayentra pr-mock examples/customer_pilot.py --pr-comment pr_review.md
```

## Workspace `ayentra.toml` Contract Discovery

Invariants can be declared inline with `@invariant(...)` and `@domain(...)` decorators or externally in `ayentra.toml`:

```toml
[[invariants]]
file = "inventory_ledger.py"
target = "InventoryLedger"
kind = "class"
expression = "self.available >= 0 and self.reserved >= 0"
check_concurrency = false
domain = { qty = { min = 1, max = 500 } }
```

## CI Onboarding & GitHub Advanced Security SARIF 2.1.0

### 1. Two-Command CI Onboarding

```bash
pip install ayentra
ayentra init --ci
```

### 2. Automated PR Review Comments

```bash
ayentra pr-mock examples/customer_pilot.py --pr-comment pr_review.md
```

### 3. GitHub Advanced Security SARIF 2.1.0 Code Scanning

```bash
ayentra check examples/customer_pilot.py --ci --sarif ayentra-report.sarif
```

## Quickstart Benchmarks & Production Verification Metrics

Ayentra was verified against 7 real-world architectural patterns spanning financial ledgers, distributed rate limiters, thread barriers, and worker queues (`dogfood_receipt.json`).

| Target Architecture | Target Module | Evaluated Cases | Caught Violation | Sandbox Status |
| :--- | :--- | :--- | :--- | :--- |
| **Financial Escrow Ledger** | `examples/customer_pilot.py` | 69 cases | Negative balance drift | `VERIFIED CANDIDATE FIX` (100%) |
| **Distributed Rate Limiter** | `redis_token_bucket.py` | 37 cases | Token underflow DoS | `VERIFIED CANDIDATE FIX` (100%) |
| **Thread Task Scheduler** | `examples/scheduler_race.py` | 1 schedule | TOCTOU preemption race | `VERIFIED CANDIDATE FIX` (100%) |
| **Inventory Ledger** | `examples/inventory_ledger.py` | 23 cases | Negative stock overdraft | `VERIFIED CANDIDATE FIX` (100%) |
| **Async Task Pipeline** | `celery_task_queue.py` | 25 cases | Dropped active tasks | `VERIFIED CANDIDATE FIX` (100%) |
| **HTTP Connection Pool** | `requests_connection_pool.py` | 6 cases | Socket exhaustion leak | `VERIFIED CANDIDATE FIX` (100%) |
| **Telemetry Sensor Parser** | `examples/data_parser.py` | 12 cases | NaN / Inf float pass-through | `VERIFIED CANDIDATE FIX` (100%) |

Explore the interactive metrics directly on the [Live Public Showcase](https://ayentra-ai.vercel.app/#dogfood).

## Quickstart

```bash
# 1. Run existing unit tests (passes on standard happy-path inputs)
pytest examples/test_existing_suite.py

# 2. Run Ayentra verification gate on individual files
ayentra check examples/scheduler_race.py --seed 42
ayentra check examples/inventory_ledger.py --seed 42
ayentra check examples/data_parser.py --seed 42

# 3. Inspect AST candidate invariant suggestions
ayentra suggest-invariants examples/inventory_ledger.py

# 4. Launch the local browser verification inspector
ayentra studio --port 8420
```
