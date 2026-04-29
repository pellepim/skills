# WebAuthn / Passkey Security Patterns

Optional module for the `/security` skill. Apply when the project implements WebAuthn/Passkey authentication.

## 1. User Verification (UV) Must Match Policy Promise

**Red Flag:**
```python
# VULNERABLE - UV only preferred, verification does not require it
authenticator_selection=AuthenticatorSelectionCriteria(
    user_verification=UserVerificationRequirement.PREFERRED,
)
# ...later...
verify_authentication_response(..., require_user_verification=False)
```

A passkey without UV is "something you have" only. If the auth policy treats a passkey as satisfying MFA (phishing-resistant), UV must be **REQUIRED** at registration AND at verification.

**Checklist:**
- [ ] `generate_registration_options` sets `user_verification=REQUIRED` (or the stored credential carries a `uv=True` flag checked before granting policy credit)
- [ ] `generate_authentication_options` sets `user_verification=REQUIRED`
- [ ] `verify_authentication_response` called with `require_user_verification=True`
- [ ] Policy code that grants "strong auth" credit reads the enforcement flag, not just credential existence

## 2. RP ID and Origin Derivation

**Red Flag:**
```python
# VULNERABLE - trusts headers that any caller can spoof
host = request.headers.get("x-forwarded-host") or request.headers.get("host")
rp_id = normalize_host(host)
```

**Checklist:**
- [ ] RP ID derives from server-side config or tenant record, not request headers
- [ ] Expected origin for verification computed from the same server-side source
- [ ] If header-derived values are kept, a `TRUSTED_PROXIES` allowlist gates `X-Forwarded-*` usage

## 3. Challenge Binding and Replay

**Checklist:**
- [ ] Challenge bytes stored server-side (session/cache), not round-tripped through client cookie or hidden field
- [ ] TTL enforced (5 min typical; longer widens replay surface)
- [ ] Session keys for the ceremony cleared on success AND on every failure branch
- [ ] Post-success code path regenerates session (prevents fixation by challenge-reuse)
- [ ] User bound to ceremony at `begin` is re-validated at `complete` (not deleted, not deactivated)

## 4. Credential Identity Binding

**Red Flag:** Matching the returned assertion against any credential in the DB rather than credentials the bound user owns.

**Checklist:**
- [ ] `allowCredentials` at begin time scoped to the pending user, not open ("discoverable") unless deliberate
- [ ] At complete time, returned `rawId` looked up within the pending user's credentials, not globally
- [ ] DB queries for update/delete/rename include `user_id` in `WHERE` clause (defense-in-depth)

## 5. Sign-Count and Clone Detection

**Checklist:**
- [ ] Sign-count regression raises a distinct error and deletes (or flags) the credential
- [ ] For `backup_eligible=True` synced credentials, sign-count check is relaxed (sync resets counter legitimately)
- [ ] Clone suspicion emits an audit event

## 6. Ceremony Payload Size

**Red Flag:**
```python
class CompleteAuthenticationRequest(BaseModel):
    response: dict  # Unbounded JSON - pre-auth DoS surface
```

`request.json()` reads the entire body before Pydantic sees it. No body cap = attacker can spray MBs per request.

**Checklist:**
- [ ] Reverse proxy or middleware caps request body size (128 KiB for auth endpoints)
- [ ] Ceremony schemas use typed sub-models with per-field `max_length`, not bare `dict`
- [ ] `rawId`, `clientDataJSON`, `attestationObject`, `authenticatorData`, `signature`, `userHandle` each have explicit length caps

## 7. Admin Revocation

**Checklist:**
- [ ] Admin-revoke path also revokes active sessions/tokens (stolen passkey usually implies stolen session)
- [ ] Unprivileged admin cannot revoke a higher-role user's passkey
- [ ] Admin cannot revoke their own passkey via admin surface (force self-service for auditability)
- [ ] Revocation emits an audit event distinguishable from self-deletion

## 8. Backup Codes / Recovery Interplay

**Checklist:**
- [ ] Backup codes issued at most once on first passkey registration; never re-issued silently
- [ ] Deleting last passkey does not leave user without a sign-in factor when policy requires one
- [ ] If multiple MFA methods share a backup-code pool, the interaction is deliberate and documented

## 9. Enumeration / Oracle Surfaces

**Checklist:**
- [ ] `begin-authentication` returns identical responses for: nonexistent user, deactivated user, zero-passkey user
- [ ] Login page does not branch on "user has passkey" unless that branch is reachable via the same oracle
- [ ] Rate limits on `begin`/`complete` share a counter with the password flow

## 10. Session Gates for Pre-Auth Flows

**Checklist:**
- [ ] Enrollment flow gated by a session key set only after baseline auth succeeded
- [ ] Gate key cleared on every exit (success, failure, timeout)
- [ ] Between `begin` and `complete`, the bound user is re-fetched and re-validated
