# pip-audit / safety / osv-scanner

Known-vulnerable dependency detection. Run at least one; `pip-audit` is the PyPA reference.

## pip-audit (recommended)

```bash
pip install pip-audit

# from installed env
pip-audit

# from a lockfile (CI-friendly)
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt

# uv / poetry / pdm
pip-audit --disable-pip   # if dependencies already resolved in env
```

Reports CVE ID, severity, fix version. Exit code non-zero on findings.

## safety

```bash
pip install safety
safety check --full-report
safety check -r requirements.txt
```

Commercial DB; free tier rate-limited. Useful as a second opinion to `pip-audit`.

## osv-scanner

```bash
brew install osv-scanner   # or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest

osv-scanner --lockfile=poetry.lock
osv-scanner --lockfile=uv.lock
osv-scanner -r .   # auto-detects multiple lockfiles
```

Backed by Google's OSV database. Strong for non-Python ecosystems too (useful in polyglot repos).

## Triage

- Triage by **exploitability in your context**, not just CVSS. A `pyyaml` CVE in a service that never accepts user YAML
  is lower priority than the same CVE on an inbound webhook.
- Pin the **fix version**, not just the next minor. Re-run after updating to confirm the alert clears.
- Transitive dependencies count. If a direct dep has no fixed version, look for a maintained fork or replace the dep.
