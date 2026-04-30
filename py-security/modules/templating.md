---
name: Python Templating Engine Security Patterns
description: Jinja2, Mako, Chameleon, Django templates - autoescape, |safe / mark_safe / Markup audit, SSTI, SVG, email-template injection
applies_to:
  - dependency: jinja2
  - dependency: mako
  - dependency: chameleon
  - dependency: genshi
  - framework: django
version: 1
last_updated: 2026-04-30
---

# Python Templating Engine Security Patterns

Apply when the project renders HTML / email templates server-side. Each engine has different
escape defaults; pitfalls below are engine-specific. Sister module to
`node-security/modules/templating.md`. Cross-link: `flask.md` and `django.md` cover
framework-specific render helpers; this module is the engine-level reference.

## 1. Jinja2

**Red Flags:**
```jinja2
{# VULNERABLE - explicit |safe on user data #}
{{ user.bio | safe }}

{# VULNERABLE - autoescape disabled at environment level #}
{% autoescape false %}{{ user.bio }}{% endautoescape %}
```

```python
# VULNERABLE - SSTI: user input as template SOURCE
from jinja2 import Template, Environment
Template(user_input).render(...)
env.from_string(user_input).render(...)
render_template_string(f"<h1>Hello {name}</h1>")                   # name="{{config}}" leaks app config

# VULNERABLE - autoescape default (depends on file extension)
env = Environment(loader=FileSystemLoader("templates"))            # autoescape=False by default!
                                                                   # only auto-on for .html/.xml/.htm via select_autoescape

# SAFE - autoescape on by default
env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml", "htm", "j2", "jinja"]))

# SAFE - render fixed template, pass user data as variable
return render_template("greeting.html", name=name)
return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

# SAFE - sandbox if user-authored templates is a feature (CMS, mail-merge)
from jinja2.sandbox import SandboxedEnvironment, ImmutableSandboxedEnvironment
env = ImmutableSandboxedEnvironment(autoescape=True)
# Assume sandbox bypass is possible. Run sandboxed renders in a separate process with seccomp / nsjail.
```

**Attack Scenario:** `render_template_string(f"Hello {request.args['name']}")` accepts `name={{config.SECRET_KEY}}`; renders the secret directly to the response.

**Checklist:**
- [ ] `Environment(autoescape=...)` set explicitly via `select_autoescape([...])`; default `autoescape=False` is the footgun
- [ ] Grep `| safe`, `Markup(`, `{% autoescape false %}`; each occurrence justified or wraps already-sanitized HTML
- [ ] No user input passed as template SOURCE: grep `Template(`, `from_string(`, `render_template_string(` for variables / f-strings / concatenation in the source argument
- [ ] User-authored templates (CMS, email-template editor) use `SandboxedEnvironment` AND run in a separate process - assume sandbox bypass exists
- [ ] Custom filters / globals do not return raw HTML from user input without escaping
- [ ] `attr_filter` and `getattr`-style lookups on user-supplied attribute names allowlisted; otherwise SSTI surface widens

## 2. Django Templates

**Red Flags:**
```django
{# VULNERABLE - mark_safe / |safe on user data #}
{{ user.bio|safe }}
{% autoescape off %}{{ user.bio }}{% endautoescape %}

{# VULNERABLE - format_html with raw user input #}
{{ user.bio }}                                 {# SAFE: auto-escaped #}
```

```python
# VULNERABLE
from django.utils.safestring import mark_safe
return mark_safe(f"<p>{user_input}</p>")                           # user_input not escaped

# VULNERABLE - Django Template engine on user input (SSTI)
from django.template import Template, Context
return Template(user_input).render(Context({}))

# VULNERABLE - format_html without escaping the dynamic part
from django.utils.html import format_html
return format_html("<p>{}</p>", user.bio)                          # OK: format_html DOES escape
return mark_safe(f"<p>{user.bio}</p>")                             # NOT OK
return format_html("<p>%s</p>" % user.bio)                         # NOT OK: % runs before format_html sees it

# SAFE
from django.utils.html import escape, format_html
return mark_safe(f"<p>{escape(user_input)}</p>")
return format_html("<p>{}</p>", user.bio)                          # placeholder values escaped automatically
```

**Checklist:**
- [ ] Grep `mark_safe(`, `SafeString(`, `|safe`, `{% autoescape off %}` - each justified
- [ ] `format_html(...)` used over `mark_safe(f"...")` for HTML composition (placeholders auto-escape; f-strings do not)
- [ ] No `Template(user_input)`, `engines["django"].from_string(user_input)`, `Engine().from_string(user_input)`
- [ ] Custom template tags / filters returning `mark_safe` audited - tag implementations must escape dynamic parts
- [ ] `{% include %}` / `{% extends %}` template names not user-controlled (path traversal across template loaders)

## 3. Mako

**Red Flags:**
```mako
${user.bio}                                                        # VULNERABLE: NOT auto-escaped by default
${user.bio | h}                                                    # SAFE: explicit escape filter
${user.bio | n}                                                    # VULNERABLE: 'n' = no escape
```

```python
# VULNERABLE - default_filters not set
from mako.template import Template
Template("${user_input}").render(user_input=value)                 # not escaped

# VULNERABLE - SSTI
Template(user_input).render(...)

# SAFE
from mako.lookup import TemplateLookup
lookup = TemplateLookup(directories=["templates"], default_filters=["h"])
```

**Checklist:**
- [ ] `default_filters=["h"]` (or `["h", "trim"]`) set on every `Template` / `TemplateLookup` - Mako does NOT auto-escape by default
- [ ] Grep `| n` (no-escape filter) and bare `${...}` without project-wide default filter; each occurrence justified
- [ ] No `Template(user_input)` - SSTI; Mako's RCE surface is large because templates can contain Python code
- [ ] Mako templates can `<% %>` execute Python - never load template files writable by lower-trust users

## 4. Chameleon (TAL/ZPT)

**Red Flags:**
```html
<p tal:content="user/bio">placeholder</p>                          <!-- SAFE: escaped by default -->
<p tal:content="structure user/bio">placeholder</p>                <!-- VULNERABLE: structure = raw HTML -->
```

**Checklist:**
- [ ] Grep `structure ` directive (TAL); each occurrence justified
- [ ] No `PageTemplate(user_input)` / `PageTemplateString(user_input)` (SSTI)
- [ ] TALES expressions can call Python; restricted via `RestrictedPython` if user-authored

## 5. Genshi (legacy)

**Checklist:**
- [ ] If still in use, plan migration; auto-escape default but unmaintained
- [ ] No user input as template source

## 6. SVG (templating-adjacent)

**Red Flags:**
```python
# VULNERABLE - inline user-uploaded SVG into HTML; <script> inside SVG executes
return f'<div>{open(uploaded_svg).read()}</div>'

# VULNERABLE - cairosvg / svglib renders <image href="https://attacker/..."> = SSRF
import cairosvg
cairosvg.svg2png(bytestring=user_svg)                              # see file-upload.md
```

**Checklist:**
- [ ] User-uploaded SVG sanitized with `bleach.clean(svg, tags=ALLOWED_SVG_TAGS, attributes=ALLOWED_SVG_ATTRS, protocols=["https"])` OR rasterized to PNG before serving
- [ ] SVG never inlined into HTML for untrusted user input - `<script>` and `<foreignObject>` enable XSS
- [ ] SVG renderers (`cairosvg`, `svglib`, `weasyprint`) treated as outbound HTTP - SSRF guard sub-resources (see SKILL.md SSRF and `file-upload.md`)

## 7. Email Template Injection

**Red Flags:**
```python
# VULNERABLE - user data in email subject / headers without sanitization
send_mail(
    subject=f"Welcome {user_name}",                                # \r\n in user_name = header injection
    from_email=user_email,                                         # never trust user-supplied From
    recipient_list=[user_email],
)

# VULNERABLE - SSTI via Jinja in mail-merge templates
template = db.email_templates.find_one(...)["body"]                # admin-authored, but if any user role can edit, SSTI
mail_body = Template(template).render(user=current_user)           # current_user.password_hash leaks via {{user.password_hash}}

# SAFE
import re
def safe_header(s: str) -> str:
    if re.search(r"[\r\n]", s): raise ValueError("header injection")
    return s
send_mail(subject=safe_header(f"Welcome {user_name}"), ...)
```

**Checklist:**
- [ ] User-controlled values reaching email headers (subject, from, reply-to, custom X- headers) reject `\r` / `\n` - or pass through `email.headerregistry` / `email.message.EmailMessage` which encode safely
- [ ] Mail-merge / template-as-data systems use `SandboxedEnvironment` AND restrict the variable namespace - do not pass full user/admin model into template context
- [ ] See `email.md` for SPF/DKIM/DMARC, link tokens, rate limits

## 8. PDF / HTML Renderers (WeasyPrint, xhtml2pdf, ReportLab, Playwright/Puppeteer-py)

**Red Flags:**
```python
# VULNERABLE - WeasyPrint fetches sub-resources (img, link[rel=stylesheet], @import)
import weasyprint
weasyprint.HTML(string=user_html).write_pdf()                      # <img src="http://169.254.169.254/..."> exfil

# VULNERABLE - xhtml2pdf same family of issues
# VULNERABLE - playwright.sync_api invoked on user content navigates the page; @font-face + DNS lookups exfil

# SAFE - disable network in renderer
weasyprint.HTML(string=user_html, base_url="local-only", url_fetcher=blocked_fetcher).write_pdf()
```

**Checklist:**
- [ ] PDF / HTML / SVG renderers on user content either disable sub-resource network fetch OR route fetches through an SSRF guard (allowlist + private-IP block + redirect re-validation)
- [ ] User content sanitized (`bleach`, `nh3`) before injection into the renderer document
- [ ] `page.evaluate(req.body.code)` patterns flagged - same as `eval` in browser context
- [ ] Headless browsers run without `--no-sandbox` if possible; if `--no-sandbox` required, run in a hardened container

## References

- OWASP XSS Prevention Cheat Sheet
- OWASP SSTI: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- Jinja2 sandbox: https://jinja.palletsprojects.com/en/stable/sandbox/
- Django escape / mark_safe: https://docs.djangoproject.com/en/stable/ref/utils/#module-django.utils.html
- bleach (HTML sanitizer): https://bleach.readthedocs.io/
- nh3 (Rust-backed sanitizer, faster bleach replacement): https://nh3.readthedocs.io/
