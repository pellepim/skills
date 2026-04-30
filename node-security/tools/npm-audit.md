# npm audit / pnpm audit / yarn audit / osv-scanner

Known-vulnerable dependency detection. Run at least one; `osv-scanner` is recommended for breadth
and CI use because the npm/yarn/pnpm built-ins differ in noise levels.

## npm audit

```bash
# Production deps only (skip devDependencies, which are usually false-positive heavy)
npm audit --omit=dev

# Apply non-breaking fixes
npm audit fix

# Force breaking upgrades to clear advisories (review the diff)
npm audit fix --force

# JSON output for CI
npm audit --json --omit=dev
```

Exit codes: non-zero on any advisory at the configured threshold (`--audit-level=moderate` or
higher).

## pnpm audit

```bash
pnpm audit --prod
pnpm audit --json --prod
```

`pnpm` resolves the workspace graph; results are typically more accurate than `npm audit` in
monorepos.

## yarn audit (Yarn 1) / yarn npm audit (Yarn 2+)

```bash
yarn audit --groups dependencies            # Yarn 1
yarn npm audit --recursive --environment production    # Yarn Berry
```

## osv-scanner (recommended)

Backed by Google's OSV database. Strong for polyglot repos and CI.

```bash
brew install osv-scanner
# or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest

osv-scanner --lockfile=package-lock.json
osv-scanner --lockfile=pnpm-lock.yaml
osv-scanner --lockfile=yarn.lock
osv-scanner -r .                            # auto-detects multiple lockfiles, including non-JS
```

## Triage

- Triage by **exploitability in your context**, not just CVSS. A `tar` slip CVE in a service that
  never extracts user-supplied archives is lower priority than the same CVE on a webhook that
  receives uploaded archives.
- Pin the **fix version**, not just the next minor. Re-run after updating to confirm the alert
  clears.
- Transitive dependencies count. If a direct dep has no fixed version, look for a maintained fork
  (`npm overrides` / `pnpm overrides` / `yarn resolutions` to force a patched transitive).
- `npm audit` reports a lot of dev-only advisories. `--omit=dev` cuts noise. For dev tooling (test
  runners, build tools), assess whether the vulnerable code path is reachable in the build (most
  are not).

## Suppression

GitHub Advisory ignores:
```bash
npm audit --audit-level=high       # only fail CI on high+
npm audit --omit=dev               # exclude dev deps
```

Per-advisory: pin to a known-good version or use `overrides` in `package.json`. Document the
reason in a comment.
