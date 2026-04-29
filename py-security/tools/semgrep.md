# semgrep

Pattern-based static analysis. Strong community rule packs for Python web frameworks.

## Install

```bash
pip install semgrep
# or
brew install semgrep
```

## Run

```bash
# OWASP Top 10 + Python rule packs (good default)
semgrep --config=p/python --config=p/owasp-top-ten --config=p/security-audit .

# Framework-specific packs
semgrep --config=p/django .
semgrep --config=p/flask .
semgrep --config=p/fastapi .

# Secrets scanning
semgrep --config=p/secrets .
```

Flags worth knowing:
- `--severity ERROR` — only highest severity
- `--exclude tests --exclude migrations`
- `--baseline-ref main` — only findings new on this branch (great for PR review)
- `--sarif --output=findings.sarif` — machine-readable output

## Per-PR scoping

```bash
semgrep --config=p/python --config=p/owasp-top-ten --baseline-ref=origin/main .
```

Reports only findings introduced relative to `main`. Pair with the headless mode in SKILL.md for diff-only review.

## Custom rules

Drop YAML rule files in `tools/semgrep-rules/` (project-specific patterns: forbidden API usage, internal-secret prefixes, banned imports). Run with `--config=tools/semgrep-rules/`.

## Suppression

Per-line: `# nosemgrep: rule-id  -- reason`. Always include reason.
