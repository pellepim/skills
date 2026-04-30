---
name: WebAuthn / Passkey Security Patterns
description: RP ID, challenge replay, UV policy, credential binding, sign-count, ceremony rate limits
applies_to:
  - feature: webauthn
  - feature: passkey
  - dependency: "@simplewebauthn/server"
  - dependency: fido2-lib
version: 1
last_updated: 2026-04-30
---

# WebAuthn / Passkey Security Patterns

Apply when the project uses WebAuthn / passkeys for registration or authentication. Most issues
arise from misconfigured RP ID, replayable challenges, or missing user-verification policy.

## 1. RP ID & Origin

**Red Flags:**
```js
// VULNERABLE - RP ID set too broadly (allows credentials to be used across subdomains the user doesn't trust)
const rpID = "example.com";                                     // OK if all subdomains are trusted; risky for shared-tenant subdomains
const rpName = "Acme";

// VULNERABLE - origin not validated on verification
verifyAuthenticationResponse({ response, expectedRPID: rpID });  // missing expectedOrigin
```

**Checklist:**
- [ ] `rpID` set to the most specific applicable domain (use `app.example.com`, not `example.com`, if `*.example.com`
      is shared with untrusted tenants)
- [ ] `expectedOrigin` allowlist on verification - exact match against app origins (including port for dev)
- [ ] `expectedRPID` matches the `rpID` used at registration

## 2. Challenge Handling

**Red Flags:**
```js
// VULNERABLE - challenge stored in cookie / localStorage where attacker can read & replay
res.cookie("challenge", challenge);

// VULNERABLE - challenge reused across ceremonies
const challenge = STATIC_CHALLENGE;
```

**Checklist:**
- [ ] Challenge is `crypto.randomBytes(≥32)` per ceremony, single-use
- [ ] Server-side session stores the challenge bound to the user (not in cookie/localStorage)
- [ ] Challenge consumed (deleted) after verification, regardless of outcome - prevents replay
- [ ] Challenge has TTL (60-300s typical)

## 3. User Verification (UV)

**Red Flags:**
```js
// VULNERABLE - UV "discouraged" on a high-value endpoint
generateAuthenticationOptions({ userVerification: "discouraged" });
```

**Checklist:**
- [ ] `userVerification: 'required'` (or at minimum `'preferred'`) for sign-in to high-value accounts
- [ ] On verification, check `flags.uv` matches the policy (server-side enforcement, not just client request)
- [ ] Step-up flows (password change, MFA enrol, money movement) require UV regardless of session UV

## 4. Sign Count

**Red Flags:**
```js
// VULNERABLE - signCount not checked; cloned authenticator goes undetected
verifyAuthenticationResponse({ /* ... */ });
// returns authenticationInfo.newCounter; if ignored, replay/cloning not detected
```

**Checklist:**
- [ ] `signCount` updated on successful verification (`newCounter > storedCounter` enforced)
- [ ] If `newCounter === 0` and `storedCounter > 0`, treat as anomaly (some authenticators don't increment - decision
      logged but not auto-rejected; up to policy)
- [ ] If `newCounter <= storedCounter` (regression), reject and alert - likely cloning

## 5. Credential Binding

**Red Flags:**
```js
// VULNERABLE - credential lookup by raw credential ID across all users (allows one user to authenticate as another
// if credential IDs are guessable or known)
const cred = await Credential.findOne({ credentialID });
const user = await User.findOne({ id: cred.userId });
```

**Checklist:**
- [ ] Authentication ceremony with `allowCredentials` populated from the user's claimed identity (post username entry,
      pre-WebAuthn) - prevents credential enumeration; OR with usernameless flows, use `userHandle` from response
- [ ] Verification confirms the credential's stored `userId` matches the session's claimed identity
- [ ] Cross-user credential reuse (one credential associated with two users) rejected at the DB level (unique
      constraint on `credentialID`)

## 6. Attestation

**Checklist:**
- [ ] Decide attestation policy explicitly: `'none'` for general consumer use, `'direct'` only when you actually verify
      attestation against an MDS (FIDO Metadata Service)
- [ ] `'indirect'` rarely useful; do not use without MDS verification
- [ ] AAGUID allowlist (if used) updated regularly

## 7. Rate Limits

**Checklist:**
- [ ] `/webauthn/authenticate/options` and `/webauthn/register/options` rate-limited per account/IP
- [ ] Verification endpoints rate-limited - prevents brute-force on PIN-protected authenticators (which the server
      cannot otherwise distinguish)

## 8. Recovery / Backup

**Checklist:**
- [ ] User-visible list of registered passkeys; revoke individual credentials
- [ ] Account recovery via verified email is the typical fallback - the recovery email's security is now critical;
      lock down email account verification
- [ ] If supporting passkey-only accounts, recovery codes generated at first registration (single-use, hashed at
      rest)

## References

- WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- @simplewebauthn/server: https://simplewebauthn.dev/docs/packages/server
