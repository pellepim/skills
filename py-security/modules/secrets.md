---
name: Secrets Management Patterns
description: Committed secrets, .env discipline, key rotation, KMS/secret-manager usage
applies_to:
  - any
version: 2
last_updated: 2026-04-30
---

# Secrets Management Patterns

Always-on module. Covers detection of committed secrets, runtime secret loading, and rotation.

## 1. Committed Secrets

**Red Flags:**
```python
# VULNERABLE - hardcoded
SECRET_KEY = "<stripe-secret-key>"
STRIPE_SECRET = "sk_test_..."
DATABASE_URL = "postgresql://admin:hunter2@prod-db:5432/app"

# VULNERABLE - .env committed
# .env  (tracked in git)
JWT_SECRET=production-jwt-secret-here

# SAFE
SECRET_KEY = os.environ["SECRET_KEY"]            # set by deploy / secret manager
DATABASE_URL = os.environ["DATABASE_URL"]
```

**Checklist:**
- [ ] Run `gitleaks detect --log-opts="origin/main..HEAD"` (see `tools/gitleaks.md`)
- [ ] `.env` in `.gitignore`; only `.env.example` (with placeholder values) committed
- [ ] No tokens / keys in `settings.py`, `config.py`, `Dockerfile`, `docker-compose.yml`, CI files
- [ ] No secrets in test fixtures that could be confused for real credentials (use clearly-fake values like
      `test-token-fake`)
- [ ] No secrets in URL strings logged by middleware (`postgresql://user:pass@...` redacted in logs)

## 2. When a Secret Leaks

**Procedure (in order):**
1. **Rotate the credential immediately.** Removing the commit does not revoke it.
2. Audit access logs for unauthorized use during the exposure window.
3. Notify on-call / security team per incident policy.
4. Optionally rewrite git history (`git filter-repo` or `BFG`) — only after rotation, only if the leaked commit has not
   been pulled by external parties.
5. Add the leaked-secret pattern to `.gitleaks.toml` allowlist *only* if it is a documented test fixture.

**Anti-pattern:** removing the secret in a follow-up commit and assuming it's gone. The git history retains it; treat as
compromised.

## 3. Runtime Loading

**Checklist:**
- [ ] Secrets loaded from environment at startup, OR from a secret manager (AWS Secrets Manager, GCP Secret Manager,
      Vault, Doppler) at request time with caching
- [ ] Secret-manager calls have a timeout and graceful failure mode (do not crash on transient outage; serve cached
      value briefly)
- [ ] Secrets not logged at any level (`logger.debug` included)
- [ ] Secrets not exposed in error pages, debug toolbars, or `/health` endpoints
- [ ] Secrets not echoed back in API responses (e.g. "your API key is X" — link the user to a separate retrieve endpoint
      with reauth)

## 4. Rotation

**Checklist:**
- [ ] Rotation procedure documented for every secret class (DB password, API keys, JWT signing keys, SECRET_KEY, OAuth
      client secrets, webhook signing secrets)
- [ ] Rotation supports overlap windows: new and old keys both valid during cutover (Django `SECRET_KEY_FALLBACKS`, JWT
      `kid` rotation, dual webhook secrets)
- [ ] Rotation does not require a deploy if possible (secret manager integration, hot reload)
- [ ] Long-lived service-account credentials replaced with short-lived tokens (workload identity, OIDC federation) where
      the platform supports it

## 5. Secret-Manager-Specific Hygiene

**AWS Secrets Manager / Parameter Store:**
- [ ] IAM policy scopes the service to specific secret ARNs, not `*`
- [ ] Secret rotation Lambda / scheduled rotation enabled where supported (RDS, DocumentDB)
- [ ] `kms:Decrypt` permission scoped to the appropriate KMS key

**HashiCorp Vault:**
- [ ] AppRole / Kubernetes auth used; no static tokens in env
- [ ] Lease durations bounded; renewals required
- [ ] Audit log enabled

**GCP Secret Manager:**
- [ ] Workload Identity Federation used for cross-cloud / external runtimes
- [ ] Versioning policy: `latest` not used in critical paths (pin a version, rotate by promoting)

## 6. CI/CD Secrets

**Checklist:**
- [ ] CI environment secrets scoped per workflow / per branch (GitHub Actions environments, GitLab protected branches)
- [ ] Pull-request workflows from forks do NOT receive production secrets
- [ ] Deploy keys scoped to one repo; not reused across repos
- [ ] Build artifacts scanned with `gitleaks` before publication (catches secrets baked into Docker images)
- [ ] `docker history` / image layer inspection does not reveal `ARG SECRET=...` (use `--mount=type=secret` in BuildKit)

## 7. Bundler / Build Artifact Leakage (Python-specific)

Python build pipelines have several non-obvious places where secrets sneak into shipped
artifacts. Server-side Python does not have a frontend bundler in the JS sense, but `wheel`,
`sdist`, container images, single-file executables, and managed-platform configs all act as
"bundlers" that can include `.env` or hardcoded credentials.

**Red Flags:**
```toml
# VULNERABLE - over-inclusive package_data / MANIFEST.in pulls .env into the wheel
# pyproject.toml
[tool.setuptools.package-data]
mypkg = ["*"]                                                      # ships every file in mypkg/, including any local .env

# MANIFEST.in
recursive-include mypkg *                                          # same risk for sdist
include .env                                                       # explicit foot-bullet
```

```dockerfile
# VULNERABLE - ARG visible in docker history; persists in image layers
ARG STRIPE_SECRET
ENV STRIPE_SECRET=$STRIPE_SECRET                                   # baked into image layer

# VULNERABLE - COPY .env into image
COPY . /app                                                        # if .env not in .dockerignore, it ships

# SAFE - BuildKit secret mount (not persisted in layers)
# syntax=docker/dockerfile:1.4
RUN --mount=type=secret,id=stripe_key \
    STRIPE_SECRET=$(cat /run/secrets/stripe_key) ./build.sh
```

```python
# VULNERABLE - Streamlit / HuggingFace Spaces - secrets file committed or readable
# .streamlit/secrets.toml committed to repo (if public Space, world-readable)
# HuggingFace Space repo is public by default; "Repository secrets" must be set via the UI,
# not as files in the repo

# VULNERABLE - PyInstaller / Nuitka single-file binary contains baked .env
# pyinstaller --add-data ".env:." main.py                          # .env shipped inside the .exe
# nuitka --include-data-file=.env=.env main.py                     # same
```

```bash
# VULNERABLE - editable install picks up uncommitted .env via package_data
pip install -e .                                                   # then `python -m mypkg` reads .env from the installed
                                                                   # location; if .env later checked in by mistake or
                                                                   # included in `python -m build`, leaks
```

**Checklist:**
- [ ] `pyproject.toml` `[tool.setuptools.package-data]` and `MANIFEST.in` reviewed - no `*`/`recursive-include ... *` patterns that pull `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `service-account*.json`
- [ ] `.dockerignore` includes `.env`, `.env.*`, `**/.env`, `*.pem`, `id_rsa*`, `.git`, `__pycache__`, `.pytest_cache`
- [ ] Dockerfile uses `--mount=type=secret` (BuildKit) for build-time secrets; never `ARG` or `ENV` for production credentials
- [ ] `docker history <image>` and `dive` against built image inspected; no `ARG SECRET=...` or copied `.env` visible in layer history
- [ ] Streamlit Cloud / HuggingFace Spaces / Replicate / Modal: secrets configured via the platform UI / managed-secret API, never committed to repo - public Spaces / Streamlit-Cloud-public apps expose any committed file
- [ ] PyInstaller / Nuitka / py2exe / cx_Freeze: `--add-data` / `include-data-file` does not include `.env`, config with secrets, or service-account JSON; `gitleaks detect` run against the produced `.exe` / single-file binary before publish (binaries embed file contents as bytes, recoverable with `strings` / `binwalk`)
- [ ] PyPI packages built from a clean checkout (CI), not the developer's working directory - prevents accidentally shipping `.env`
- [ ] `python -m build` output (`dist/*.whl`, `dist/*.tar.gz`) inspected once before first publish: `unzip -l dist/*.whl` / `tar tzf dist/*.tar.gz` reviewed for stray secrets / config files
- [ ] Editable installs (`pip install -e .`) audited - `<package>.egg-info/SOURCES.txt` lists everything packaged; should not include `.env`
- [ ] Lambda / Cloud Run / serverless deploys: deployment package built from a CI artifact, not local `zip`; CI job has `.env` excluded from the build context

## 8. Local Development

**Checklist:**
- [ ] `.env.example` committed with placeholder values; real `.env` ignored
- [ ] Local development uses *non-production* credentials (separate Stripe test mode, separate AWS dev account)
- [ ] Direnv / `dotenv` setup documented; developers do not paste prod secrets locally

## References

- Gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- OWASP Secrets Management Cheat Sheet
