---
name: Templating Engine Security Patterns
description: EJS, Pug, Handlebars, Nunjucks, React SSR (dangerouslySetInnerHTML), template injection
applies_to:
  - dependency: ejs
  - dependency: pug
  - dependency: handlebars
  - dependency: nunjucks
  - dependency: mustache
  - dependency: hbs
  - dependency: react-dom
version: 1
last_updated: 2026-04-30
---

# Templating Engine Security Patterns

Apply when the project renders HTML / email templates server-side. Each engine has different
escape defaults; the pitfalls below are engine-specific.

## 1. EJS

**Red Flags:**
```ejs
<%- user.bio %>                    <!-- VULNERABLE: unescaped output -->
<%= user.bio %>                    <!-- SAFE: HTML-escaped -->
```

**Checklist:**
- [ ] Grep for `<%- ` (unescaped tag); each occurrence justified or wraps user input in DOMPurify-equivalent
- [ ] EJS version pinned: `ejs` had RCE via `outputFunctionName` template option (CVE-2022-29078) - use ≥3.1.10
- [ ] No `ejs.render(userTemplate, data)` (SSTI); only `ejs.render(staticTemplate, data)`
- [ ] `includes` / partials use static paths, not user-controlled

## 2. Pug

**Red Flags:**
```pug
!= user.bio                        // VULNERABLE: unescaped
= user.bio                         // SAFE: escaped
```

**Checklist:**
- [ ] Grep for `!=` and `!{...}`; each occurrence justified
- [ ] No `pug.compile(userInput)` / `pug.render(userInput, data)` (SSTI)

## 3. Handlebars

**Red Flags:**
```handlebars
{{{ user.bio }}}                   <!-- VULNERABLE: triple-stash unescaped -->
{{ user.bio }}                     <!-- SAFE -->
```

**Checklist:**
- [ ] Grep for `{{{` (triple-stash); each occurrence justified
- [ ] No `Handlebars.compile(userInput)`; only static templates
- [ ] Custom helpers do not return `new Handlebars.SafeString(userInput)` without sanitization
- [ ] `{{#noEscape}}` blocks (custom helper) audited

## 4. Nunjucks

**Red Flags:**
```jinja2
{{ user.bio | safe }}              VULNERABLE: marks safe without sanitizing
{{ user.bio }}                     SAFE: auto-escaped
```

**Checklist:**
- [ ] `autoescape: true` (default) - never disable globally
- [ ] Grep for `| safe`; each occurrence justified
- [ ] No `nunjucks.renderString(userInput, data)` (SSTI)

## 5. Mustache (logic-less, low risk)

**Checklist:**
- [ ] `{{{ }}}` (unescaped) audited; default `{{ }}` is safe
- [ ] No template source from user input

## 6. React Server-Side Rendering

**Red Flags:**
```jsx
// VULNERABLE - user-controlled HTML
<div dangerouslySetInnerHTML={{ __html: post.body }} />

// VULNERABLE - href / src injection
<a href={user.website}>...</a>                                  // user.website = "javascript:alert(1)"

// VULNERABLE - rendering objects with arbitrary keys via JSX spread
<div {...user.attrs} />                                         // attrs.dangerouslySetInnerHTML possible
```

**Checklist:**
- [ ] `dangerouslySetInnerHTML` audited; user input wrapped in `DOMPurify.sanitize(html, { USE_PROFILES: { html:
      true } })`
- [ ] User-supplied URLs (`href`, `src`, `formaction`) validated to start with `https://` or `/`; reject
      `javascript:`, `data:`, `vbscript:` schemes
- [ ] JSX spread (`{...obj}`) not used with user-controlled objects (allows injecting `dangerouslySetInnerHTML`)
- [ ] When generating HTML for emails / non-React contexts, prefer `mjml` or template engines with auto-escape, not
      string concatenation
- [ ] `eslint-plugin-react` `react/no-danger` and `react/jsx-no-script-url` enabled

## 7. SVG (templating-adjacent)

**Checklist:**
- [ ] User-uploaded SVG sanitized with `DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true, svgFilters: true } })`
      OR rasterized to PNG before serving
- [ ] SVG never inlined into HTML for untrusted user input (XSS via `<script>` inside SVG)

## 8. PDF / Email HTML Renderers (Puppeteer, MJML, Handlebars-via-mailer)

**Checklist:**
- [ ] Puppeteer / Playwright invocations on user content go through SSRF guard for sub-resources (see SKILL.md "SSRF")
- [ ] User content sanitized before injection into the renderer document
- [ ] `page.evaluate(req.body.code)` patterns flagged - same as `eval` in browser context
- [ ] Headless browsers run without `--no-sandbox` if possible; if `--no-sandbox` required, run in a hardened container

## References

- OWASP XSS Prevention Cheat Sheet
- DOMPurify: https://github.com/cure53/DOMPurify
