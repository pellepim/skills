---
name: Secrets Management Patterns
description: Committed secrets, .env discipline, key rotation, KMS/secret-manager usage
applies_to:
  - any
version: 1
last_updated: 2026-04-29
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

## 7. Local Development

**Checklist:**
- [ ] `.env.example` committed with placeholder values; real `.env` ignored
- [ ] Local development uses *non-production* credentials (separate Stripe test mode, separate AWS dev account)
- [ ] Direnv / `dotenv` setup documented; developers do not paste prod secrets locally

## References

- Gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- OWASP Secrets Management Cheat Sheet
