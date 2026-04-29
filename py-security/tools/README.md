# Static Analyzer Pre-Pass

Run these before manual review. They are cheap and catch the obvious cases (`eval`, `pickle.loads`, `shell=True`, `verify=False`, hardcoded secrets, known-vulnerable dependencies). Manual review focuses on what tools cannot see: auth logic, IDOR, policy consistency, business logic.

## Order of operations

1. `pip-audit` / `safety` — known-vulnerable dependencies
2. `bandit` (or `ruff --select=S`) — Python security lints
3. `semgrep` — pattern-based, broader rule packs
4. `gitleaks` — committed secrets
5. Manual review with SKILL.md + matched modules

## Invocations

See individual files in this directory. Each is a one-liner intended to be run from the project root.

## Triage

- **High-confidence findings** (e.g. `verify=False`, `pickle.loads(request.body)`, `shell=True` with f-string): include directly in the report.
- **Medium-confidence** (e.g. bandit `B608` SQL string formatting): verify the call site is reachable with user input before reporting.
- **Low-confidence / known false positives** (e.g. bandit `B101` assert, `B311` random in non-security context): suppress with a per-rule justification or in-line `# nosec` with reason.

Tool output is a starting point, not the report.
