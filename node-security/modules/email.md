---
name: Email Sending Security Patterns
description: Header injection, link tokens, SPF/DKIM/DMARC, rate limits, inbound mail, template injection
applies_to:
  - feature: email
  - dependency: nodemailer
  - dependency: "@sendgrid/mail"
  - dependency: mailgun-js
  - dependency: postmark
  - dependency: resend
  - dependency: "@aws-sdk/client-ses"
version: 1
last_updated: 2026-04-30
---

# Email Sending Security Patterns

Apply when the project sends transactional or notification email.

## 1. Header Injection

**Red Flags:**
```js
// VULNERABLE - user-controlled value in header / Reply-To
transport.sendMail({
  from: "no-reply@example.com",
  to: req.body.email,                                           // can include CR/LF if not validated
  subject: req.body.subject,                                    // CRLF in subject splits headers and injects new ones
  replyTo: req.body.contact,
});
```

**Checklist:**
- [ ] Email addresses validated by a mail library / regex that rejects CR/LF and most control characters
- [ ] Subject and other header values stripped of CR/LF (`\r`, `\n`, ``, ` `, ` `)
- [ ] Use `address` objects (`{ name, address }`) so the library handles encoding (RFC 2047 / 5322)
- [ ] `Bcc` list deduplicated server-side; do not echo recipient list in the body

## 2. Link Tokens (Verify, Reset, Magic Link)

**Red Flags:**
```js
// VULNERABLE - predictable token
const token = `${userId}-${Date.now()}`;

// VULNERABLE - token reusable / no expiry
await User.update({ id }, { resetToken: token });
// no expiry, no single-use
```

**Checklist:**
- [ ] Tokens are `crypto.randomBytes(≥32).toString("base64url")` - never `Math.random`, never sequential
- [ ] Tokens stored as hashes in DB (`bcrypt` / `crypto.createHash('sha256')`); compared with `timingSafeEqual` - so DB
      leak does not yield reusable tokens
- [ ] TTL bounded (15-60 min for password reset; 24h for verify)
- [ ] Single-use: marked consumed atomically (`UPDATE ... WHERE token=X AND used=false`)
- [ ] Old tokens for the same user invalidated on new request (do not stack)
- [ ] Link target is HTTPS, on the canonical domain, with the token in path or query (NOT in fragment)

## 3. Sender Verification (SPF / DKIM / DMARC)

**Checklist:**
- [ ] Sending domain has SPF, DKIM, DMARC records (DMARC at `p=quarantine` or `p=reject` for sending domains)
- [ ] BIMI considered for brand visibility (requires DMARC enforcement)
- [ ] Subdomain dedicated for transactional mail (`mail.example.com`) so a deliverability incident does not impact the
      apex domain

## 4. Rate Limits / Cost Amplification

**Red Flags:**
```js
// VULNERABLE - signup/forgot-password sends email without per-account rate limit
app.post("/forgot", async (req) => {
  const user = await User.findOne({ email: req.body.email });
  if (user) await sendResetEmail(user);
  res.send("ok");                                                // attacker hammers this -> mailbomb victim, drives up SES bill
});
```

**Checklist:**
- [ ] Per-recipient rate limit on transactional emails (forgot password, verify, magic link) - max 1 per 60s per
      address
- [ ] Per-IP rate limit on the trigger endpoint
- [ ] Generic response on /forgot regardless of whether the account exists (prevents enumeration)
- [ ] Bounce handling pauses sending to addresses that hard-bounced (avoid IP/domain reputation damage)

## 5. Template Injection

**Red Flags:**
```js
// VULNERABLE - user input as template source
const tmpl = Handlebars.compile(req.body.body);
sendMail({ html: tmpl({ user }) });

// VULNERABLE - HTML body interpolated raw (user content as HTML)
sendMail({ html: `<p>Hello ${userName}</p>` });                  // userName has <script> -> renders in some clients
```

**Checklist:**
- [ ] Template source is server-authored; user input only as variables
- [ ] User-provided fields HTML-escaped (or rendered through a template engine that escapes by default)
- [ ] User-provided URLs validated to start with `https://`; reject `javascript:`, `data:`
- [ ] Inline images / attachments not from user input unless uploaded via the app's own pipeline

## 6. Inbound Mail (Receiving)

**Checklist:**
- [ ] Inbound mail webhooks (SES inbound, SendGrid Inbound Parse, Mailgun routes) verify HMAC signature - see SKILL.md
      "Webhook Signature Verification"
- [ ] DKIM verification on inbound; reject / quarantine messages with failed DKIM if domain authority matters
- [ ] Attachments handled with `modules/file-upload.md` rules (size cap, type allowlist, malware scan)
- [ ] Reply-tracking tokens stored as opaque IDs; do not embed user IDs in plaintext

## 7. Bounce / Complaint Handling

**Checklist:**
- [ ] SNS / webhook handlers for bounce + complaint events update suppression list
- [ ] Suppression list checked before sending - hard-bounced or complained addresses skipped
- [ ] User-visible "unsubscribe" link in marketing emails (List-Unsubscribe header for transactional opt-out)

## 8. Provider Credentials

**Checklist:**
- [ ] API keys / SMTP credentials in secret manager; not committed
- [ ] Provider-side IP allowlist (where supported) - reduces blast radius if a key leaks
- [ ] Send-rate quotas configured at the provider; alert on quota near-cap

## References

- DMARC: https://datatracker.ietf.org/doc/html/rfc7489
- OWASP Email Header Injection
