---
name: <module name, e.g. "Redis Security Patterns">
description: <one-line summary used by the orchestrator to decide relevance>
applies_to:
  # One or more triggers. Orchestrator reads project state and matches.
  - feature: <e.g. saml, oauth2, file-upload, graphql, websocket, email, multi-tenancy, task-queue, webauthn>
  # OR
  - framework: <e.g. django, fastapi, flask, drf>
  # OR
  - dependency: <pypi package name to detect via requirements.txt / pyproject.toml>
  # OR
  - any  # always-on (use sparingly)
version: 1
last_updated: YYYY-MM-DD
---

# <Module Name> Security Patterns

One-paragraph scope statement. When this module applies. What it does NOT cover (link sister modules).

## 1. <Risk Name>

**Red Flags:**
```python
# VULNERABLE - one-line reason
<minimal vulnerable example>

# SAFE - one-line reason
<minimal safe example>
```

**Attack Scenario:** One sentence: how attacker reaches this code path and what they get.

**Checklist:**
- [ ] Concrete check 1 (greppable when possible)
- [ ] Concrete check 2

## 2. <Next Risk>

...

## References

- Link to spec / advisory / CVE / OWASP cheatsheet

---

## Module Authoring Rules

(Delete this section in the real module.)

1. **Every risk has a Checklist.** Code examples optional, checklist mandatory. Reviewers grep checklists.
2. **Checklist items are greppable when possible.** "No `pickle.loads` on untrusted data" beats "Avoid unsafe
   deserialization."
3. **Vulnerable AND safe examples paired.** Showing the fix matters more than naming the bug.
4. **Attack Scenario is one sentence, not a paragraph.** If it needs more, the risk is two risks.
5. **Bump `version` on substantive checklist change.** Cosmetic edits do not bump.
6. **Update `last_updated` on every merge.**
7. **`applies_to` is the contract.** Orchestrator uses it to auto-load. Wrong value = skipped or noise.
8. **Cross-link sister modules.** "See `file-upload.md` for archive extraction" beats duplicating.
9. **No prose without a pattern.** If you cannot turn the advice into a Red Flag or Checklist item, it does not belong
   here.
10. **Test the module by reviewing a real PR with it.** If checklist items did not fire when they should, fix the
    wording.
