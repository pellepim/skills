# Static Analyzer Pre-Pass

Run these before manual review. They are cheap and catch the obvious cases (`eval`,
`child_process.exec` with interpolation, `rejectUnauthorized: false`, hardcoded secrets, known-
vulnerable dependencies). Manual review focuses on what tools cannot see: auth logic, IDOR, policy
consistency, business logic.

## Order of operations

1. `npm audit` / `pnpm audit` / `yarn audit` / `osv-scanner` - known-vulnerable dependencies
2. `eslint-plugin-security` (or `eslint-plugin-no-unsanitized`) - JS/TS security lints
3. `semgrep` - pattern-based, broader rule packs
4. `gitleaks` - committed secrets
5. Manual review with SKILL.md + matched modules

## Invocations

See individual files in this directory. Each is a one-liner intended to be run from the project
root.

## Triage

- **High-confidence findings** (e.g. `child_process.exec` with template literal, `eval(req.body)`,
  `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`): include directly in the report.
- **Medium-confidence** (e.g. `eslint-plugin-security` `detect-object-injection`, semgrep
  `javascript.lang.security.audit.dangerously-set-inner-html`): verify the call site is reachable
  with user input before reporting. `detect-object-injection` is famously noisy.
- **Low-confidence / known false positives**: suppress with a per-rule justification or in-line
  `// eslint-disable-next-line ... -- reason` / `// nosemgrep: rule-id -- reason`.

Tool output is a starting point, not the report.
