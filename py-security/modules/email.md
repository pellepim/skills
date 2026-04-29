# Email Security Patterns

Optional module for the `/security` skill. Apply when the project sends outbound emails (transactional, notification, marketing) or processes inbound email.

## 1. Header Injection

**Red Flags:**
```python
# VULNERABLE - user input in email headers
subject = request.form["subject"]
msg = MIMEText(body)
msg["Subject"] = subject  # Newline in subject = header injection
msg["To"] = user_email     # If user_email contains \r\n, attacker injects headers

# SAFE - sanitize or use library that handles it
subject = request.form["subject"].replace("\r", "").replace("\n", "")
# Or use a library that rejects/escapes control characters (most modern ones do)
```

```python
# VULNERABLE - user input in From/Reply-To
msg["Reply-To"] = request.form["reply_to"]  # Attacker controls reply destination

# SAFE - Reply-To from allowlist or fixed
msg["Reply-To"] = settings.SUPPORT_EMAIL
```

**Checklist:**
- [ ] All header values sanitized for `\r\n` (CRLF injection)
- [ ] `To`, `Cc`, `Bcc` addresses validated as email format before use
- [ ] `From` and `Reply-To` set from server config, not user input
- [ ] `Subject` sanitized or truncated (no newlines)
- [ ] Email library used handles header encoding (RFC 2047) automatically

## 2. Template Injection / SSRF

**Red Flags:**
```python
# VULNERABLE - user input in template rendering
template = jinja2.Template(user_provided_template)
html = template.render(context)  # SSTI: Server-Side Template Injection
send_email(html=html)

# VULNERABLE - email template fetches remote resources
html = f'<img src="{user_provided_url}">'  # SSRF when email renderer fetches image
```

**Checklist:**
- [ ] Email templates are developer-authored, never user-provided raw templates
- [ ] User content interpolated via safe template variables (auto-escaped)
- [ ] No remote resource fetching in email body (inline or data URIs for images)
- [ ] If using Jinja2/Django templates for emails, sandbox enabled for user-facing templates
- [ ] `{{ }}` expressions in email templates escape HTML (prevent XSS in webmail clients)

## 3. Sensitive Data in Emails

**Checklist:**
- [ ] Passwords never sent in email (send reset links instead)
- [ ] Tokens in email links are single-use and time-limited
- [ ] Email links use HTTPS
- [ ] PII minimized in email body (link to authenticated page for details)
- [ ] Email bodies not stored in logs at full fidelity
- [ ] Bounce/failure notifications do not echo full original message to third parties

## 4. SPF / DKIM / DMARC Configuration

Not code-level, but the security agent should flag if the application sends email from domains without proper authentication:

**Checklist:**
- [ ] `From` domain has SPF record (or application uses an authenticated relay that does)
- [ ] DKIM signing configured (via SMTP provider or application-level)
- [ ] DMARC policy published for sending domain
- [ ] Application does not send from domains it does not control
- [ ] Envelope sender (`MAIL FROM`) matches header `From` domain (alignment)

## 5. Rate Limiting on Email-Triggering Endpoints

**Red Flags:**
```python
# VULNERABLE - unauthenticated endpoint sends email without rate limit
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form["email"]
    user = db.get_user_by_email(email)
    if user:
        send_reset_email(user)  # Attacker can spam any email address
    return {"status": "ok"}  # Same response regardless (good for enumeration, bad for rate limiting)
```

**Checklist:**
- [ ] Password reset, invitation, verification endpoints rate-limited per IP and per email address
- [ ] Rate limit applies even when user not found (prevent enumeration via timing)
- [ ] Cooldown period between emails to the same address (e.g., 1 per minute, 5 per hour)
- [ ] Email sending failures do not bypass rate limit tracking
- [ ] Bulk email operations (admin invitations) have separate, higher limits with admin auth

## 6. Bounce and Complaint Handling

**Checklist:**
- [ ] Hard bounces tracked and suppressed (do not keep sending to invalid addresses)
- [ ] Complaint/spam reports processed (unsubscribe the reporter)
- [ ] Bounce processing endpoint (webhook) authenticated or signature-verified
- [ ] Bounce logs do not store full email content (PII exposure via log access)
- [ ] Suppression list checked before sending (avoid repeated bounces degrading sender reputation)

## 7. Email Link Security

**Red Flags:**
```python
# VULNERABLE - predictable token
token = str(user.id) + str(int(time.time()))  # Guessable
reset_url = f"https://app.com/reset?token={token}"

# SAFE
token = secrets.token_urlsafe(32)
store_token(user.id, token, expires=timedelta(hours=1))
reset_url = f"https://app.com/reset?token={token}"
```

**Checklist:**
- [ ] Tokens cryptographically random (`secrets.token_urlsafe(32)` or equivalent)
- [ ] Tokens single-use (consumed on first use)
- [ ] Tokens time-limited (1 hour for reset, 24-72 hours for invitation)
- [ ] Token invalidated when superseded (new reset request invalidates old token)
- [ ] Link points to HTTPS endpoint
- [ ] Redirect after token consumption does not leak token in `Referer` header

## 8. Inbound Email Processing

If the application processes incoming email (support tickets, reply-by-email):

**Checklist:**
- [ ] Sender address not trusted for authentication (easily spoofed)
- [ ] Inbound webhook authenticated (signature verification from provider)
- [ ] Attachments treated as untrusted file uploads (see `file-upload.md` module)
- [ ] HTML email body sanitized before display (XSS via email content)
- [ ] Email size limits enforced (reject oversized messages before processing)
- [ ] Reply-to-address tokens are unguessable (prevent unauthorized replies)
