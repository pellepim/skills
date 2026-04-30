# semgrep

Pattern-based static analysis. Strong community rule packs for JS/TS frameworks.

## Install

```bash
brew install semgrep
# or: pip install semgrep
```

## Run

```bash
# OWASP Top 10 + JS/TS rule packs (good default)
semgrep --config=p/javascript --config=p/typescript \
        --config=p/owasp-top-ten --config=p/security-audit .

# Framework-specific packs
semgrep --config=p/express .
semgrep --config=p/nestjs .
semgrep --config=p/nextjs .
semgrep --config=p/react .

# Secrets scanning
semgrep --config=p/secrets .
```

Flags worth knowing:
- `--severity ERROR` - only highest severity
- `--exclude __tests__ --exclude node_modules --exclude dist --exclude build`
- `--baseline-ref main` - only findings new on this branch (great for PR review)
- `--sarif --output=findings.sarif` - machine-readable output (GitHub code-scanning compatible)

## Per-PR scoping

```bash
semgrep --config=p/javascript --config=p/typescript --config=p/owasp-top-ten \
        --baseline-ref=origin/main .
```

Reports only findings introduced relative to `main`. Pair with the headless mode in SKILL.md for
diff-only review.

## Custom rules

Drop YAML rule files in `tools/semgrep-rules/` (project-specific patterns: forbidden API usage,
internal-secret prefixes, banned imports). Run with `--config=tools/semgrep-rules/`.

## Suppression

Per-line: `// nosemgrep: rule-id -- reason`. Always include reason.

## Notes

- Semgrep's `p/javascript` and `p/typescript` overlap. Run both for TS projects; the typescript
  pack adds type-aware patterns.
- Path-traversal and SSRF rules are intentionally heuristic. Treat their output as candidates for
  manual review, not as ground truth.
- For monorepos, scope per package: `semgrep --config=p/javascript packages/api/`.
