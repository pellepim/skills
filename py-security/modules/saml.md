# SAML Security Patterns

Optional module for the `/security` skill. Apply when the project implements SAML SP or IdP functionality.

## XML Signature Wrapping (XSW)

- [ ] Signature validation covers the entire assertion, not just a fragment
- [ ] Signed elements cannot be moved or duplicated within the XML
- [ ] SAML library configuration enforces strict signature validation
- [ ] If using `python3-saml`, `wantAssertionsSigned` and `wantMessagesSigned` are enabled

## Assertion Replay

- [ ] Assertions include unique IDs and are validated for reuse
- [ ] `NotOnOrAfter` / `NotBefore` timing constraints are enforced
- [ ] Replay protection via nonce tracking or short validity windows

## Audience Restriction Bypass

- [ ] `Audience` element matches the expected SP entity ID
- [ ] Assertions intended for one SP cannot be replayed to another

## IdP-side (Issuing Assertions)

- [ ] Signing keys are properly protected (not logged, not in plaintext config)
- [ ] Per-SP certificate isolation (SP A's cert does not sign SP B's assertions)
- [ ] Consent flow cannot be bypassed (direct POST to assertion endpoint)
- [ ] `NameID` and attribute values are properly escaped in assertion XML

## Metadata Security

- [ ] Metadata endpoints do not leak private keys
- [ ] Metadata URL imports validate the fetched XML
- [ ] SSRF protection on metadata URL fetching (deny internal/private IP ranges)

## Common Red Flags

```python
# VULNERABLE - no audience validation
assertion = parse_saml_response(raw_xml)
user = lookup_user(assertion.name_id)  # Trusts any assertion

# SAFE
assertion = parse_saml_response(raw_xml)
if assertion.audience != expected_entity_id:
    raise SecurityError("Audience mismatch")
```

```python
# VULNERABLE - no replay check
if assertion.not_on_or_after > now():
    accept(assertion)

# SAFE
if assertion.not_on_or_after > now() and not already_used(assertion.id):
    mark_used(assertion.id, ttl=assertion.not_on_or_after)
    accept(assertion)
```
