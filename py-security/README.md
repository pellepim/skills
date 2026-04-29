# py-security

Security review skill for Python projects. Identifies OWASP Top 10 vulnerabilities and a handful of
cross-cutting categories (unbounded input, ReDoS, TOCTOU, policy consistency) using concrete red-flag
patterns and grep-able checklists.

> Looking for the full checklist used during a review? See [`SKILL.md`](./SKILL.md).

## Elevator Pitch

`py-security` maps the OWASP Top 10 plus several cross-cutting categories into concrete red-flag patterns
and grep-able checklists. Point it at a branch and it runs a static-analyzer pre-pass (`pip-audit`,
`ruff S`, `semgrep`, `gitleaks`), then does a manual review for the things tools cannot see: IDOR, auth
logic, business-rule consistency, mass assignment, SSRF guards, webhook signature verification. Output is
a structured findings report with severity, attack scenario, and specific remediation. It will not modify
code.

## How It Runs

Two modes:

- **Interactive.** Invoke the skill, it asks for scope, focus, and prior context, then walks the
  categories.
- **Headless.** Hand it a file list (or let it diff against `origin/main`) and it produces a report you
  can drop in a PR.

Either way, every finding cites `file:line`, and every clean category cites `file:line` evidence too.
"Looks fine" is rejected; a negative finding must point at the parameterized query, the ownership check,
the `algorithms=["RS256"]` pin that proves the absence of the issue. That keeps reviewer-trust high and
stops "I checked, all good" reports from sneaking through.

Severity is governed by a per-category rubric (e.g. `pickle.loads` on untrusted input is Critical;
missing security headers is Low), so severity does not drift between reviewers or between runs.

## Modules

The piece worth knowing as a contributor is the module system in [`modules/`](./modules). Each module
declares `applies_to:` triggers (framework, dependency, feature, or `any`) in frontmatter, and the skill
auto-loads the matching ones at scan start based on imports and lockfiles. A Django+SAML repo gets
different checklists than a FastAPI+Stripe repo without anyone having to remember to ask for them.

Adding coverage for a new framework or feature is a copy of [`modules/_template.md`](./modules/_template.md).
No edit to `SKILL.md` needed.

## Practical Usage

- Run it on every non-trivial PR. Diff-only mode is cheap.
- Use the static pre-pass output as the floor; treat manual checklists as the ceiling.
- When you see a finding you disagree with, push back with a `file:line` of the safe pattern. That same
  evidence is what the report will cite next time, and the skill gets sharper over time.

## Wiring It Up

Claude Code discovers skills under `~/.claude/skills/` (user-global) or `.claude/skills/` inside a
project. Symlink this directory into the discovery path:

```bash
# user-global
mkdir -p ~/.claude/skills
ln -s "$(pwd)" ~/.claude/skills/py-security

# project-local
mkdir -p /path/to/target-repo/.claude/skills
ln -s "$(pwd)" /path/to/target-repo/.claude/skills/py-security
```

See the [repo root README](../README.md#invoking-a-skill) for headless / CI invocation examples.

## What It Does Not Do

- No code fixes. Reports findings only.
- No penetration testing. Code review only.
- No assumptions. Verifies against actual usage.
