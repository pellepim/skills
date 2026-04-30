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

Either way, the format asks every finding to cite `file:line`, and every clean category to cite
`file:line` evidence too. "Looks fine" without a citation is rejected by the SKILL.md contract; a
negative finding is supposed to point at the parameterized query, the ownership check, the
`algorithms=["RS256"]` pin that proves the absence of the issue. The agent can still get this wrong,
but the format raises the bar above "I checked, all good".

Severity is governed by a per-category rubric (e.g. `pickle.loads` on untrusted input is Critical;
missing security headers is Low). Reviewers still interpret edge cases, but the rubric reduces drift
between reviewers and between runs.

## Modules

Modules live in [`modules/`](./modules). Each declares `applies_to:` triggers (framework, dependency,
feature, or `any`) in frontmatter; SKILL.md instructs the agent to match these against project imports
and lockfiles at scan start and load the matching modules. A Django+SAML repo and a FastAPI+Stripe repo
end up with different checklists. Match quality depends on the agent following the discovery procedure
correctly; a mis-detected dependency can mean a skipped module.

Adding coverage for a new framework or feature is a copy of [`modules/_template.md`](./modules/_template.md).
No edit to `SKILL.md` needed.

## Practical Usage

- Run it on every non-trivial PR. Diff-only mode is cheap.
- Use the static pre-pass output as the floor; treat manual checklists as the ceiling.
- When you disagree with a finding, push back with a `file:line` of the safe pattern. There is no
  automatic learning loop: the skill is static markdown, fresh per run. To make pushback stick, edit
  the relevant module to refine the checklist wording, or capture the project-specific safe pattern
  in `CLAUDE.md` so subsequent runs see it as context.

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
- No runtime testing. Static review of the source as committed.
- Not a substitute for human review on high-impact changes (auth, payments, data export). The skill
  flags known patterns; novel logic bugs and business-rule flaws still need human eyes.
