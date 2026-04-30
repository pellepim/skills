---
name: Next.js API & Server Security Patterns
description: API routes, App Router server actions, middleware, getServerSideProps, env exposure, image optimization, RSC leakage
applies_to:
  - framework: next-api
  - dependency: next
version: 1
last_updated: 2026-04-30
---

# Next.js API & Server Security Patterns

Apply when the project uses Next.js (Pages Router `pages/api/`, App Router `app/api/`, Server
Actions, Server Components, or `middleware.ts`). Covers server-side surface only - client-side XSS
covered in SKILL.md.

## 1. Auth Middleware (`middleware.ts`)

**Red Flags:**
```ts
// VULNERABLE - matcher excludes /api by mistake
export const config = { matcher: ["/((?!_next|api).*)"] };      // /api/* not protected

// VULNERABLE - middleware runs but only checks cookie existence
export function middleware(req: NextRequest) {
  if (!req.cookies.get("session")) return NextResponse.redirect("/login");
  return NextResponse.next();                                   // existence != validity
}
```

**Checklist:**
- [ ] `matcher` covers all protected paths including `/api/*` (or matcher omitted for global)
- [ ] Session/JWT *verified* in middleware (signature + expiry), not just presence-checked
- [ ] Edge runtime crypto: use Web Crypto API; `crypto` module is restricted at the edge
- [ ] Middleware does not leak which paths exist (use the same response for "not authed" and "not found" if needed)

## 2. API Routes (Pages Router) / Route Handlers (App Router)

**Red Flags:**
```ts
// VULNERABLE - no method check; same handler for GET and DELETE
export default function handler(req, res) {
  return db.delete(req.query.id);                               // CSRF if cookie auth + no method check
}

// VULNERABLE - no body validation
export async function POST(req: Request) {
  const body = await req.json();
  await User.create(body);                                      // mass assignment
}
```

**Checklist:**
- [ ] Method check or App Router named exports (`export async function GET / POST`) - do not handle multiple methods
      from one function without `if (req.method !== ...)` guard
- [ ] Body validated with zod / yup / valibot / ajv; no `User.create(body)` patterns
- [ ] Auth check at top of handler (or in shared `requireUser(req)` helper); not assumed to be done by middleware unless
      verified
- [ ] CSRF: App Router default fetcher sends `Origin`; verify on state-changing handlers, OR rely on `SameSite=Lax`
      cookies, OR use bearer tokens

## 3. Server Actions (App Router)

**Red Flags:**
```tsx
// VULNERABLE - server action without auth check; invokable by anyone with a network tap
"use server";
export async function deleteUser(id: string) {
  await db.user.delete({ where: { id } });
}

// VULNERABLE - server action accepts unvalidated input
export async function updateProfile(data: FormData) {
  await db.user.update({ data: Object.fromEntries(data) });     // mass assignment
}
```

**Checklist:**
- [ ] Every `"use server"` function performs auth + authz before any DB write
- [ ] Server actions validate `FormData` / inputs with a schema before passing to ORM
- [ ] Server actions are POST-only by design but are publicly callable; treat them like API routes for security
      purposes (rate limit, auth, validation)
- [ ] Sensitive server actions check Origin/Referer header to prevent CSRF when used with cookie auth
- [ ] Actions invoked from Server Components do NOT skip checks - the action body runs even when called from a
      client-side fetch with the right action ID

## 4. Server Components / Data Leakage

**Red Flags:**
```tsx
// VULNERABLE - server component returns full ORM model to client component
async function ProfilePage({ userId }) {
  const user = await db.user.findUnique({ where: { id: userId } });
  return <ProfileClient user={user} />;                          // passwordHash, mfaSecret serialized to client
}
```

**Checklist:**
- [ ] Data passed from Server Components to Client Components is filtered to public fields only
- [ ] No `passwordHash`, `mfaSecret`, `apiKey`, internal IDs leaked via server-rendered props
- [ ] `JSON.stringify`-able sensitive values reviewed - they appear in HTML payload as `__next_f` data
- [ ] React Server Component "taint" API used for high-sensitivity fields where supported

## 5. Environment Variables

**Red Flags:**
```js
// VULNERABLE - server secret used in client component (Next inlines NEXT_PUBLIC_ vars only,
// but importing a server-only module from a client component leaks)
"use client";
import { adminToken } from "../config";                         // bundled into client JS
```

**Checklist:**
- [ ] Only `NEXT_PUBLIC_*` env vars referenced from client components / browser-bound code
- [ ] `import "server-only"` at top of modules that should never bundle client-side
- [ ] Build artifacts (`.next/static/`) inspected for secrets after build (`gitleaks dir .next/`)
- [ ] `next.config.js` `env` field does not promote server secrets to the client bundle

## 6. getServerSideProps / getStaticProps (Pages Router)

**Red Flags:**
```ts
// VULNERABLE - returns ORM model directly in props
export const getServerSideProps = async ({ params }) => {
  const user = await db.user.findUnique({ where: { id: params.id } });
  return { props: { user } };                                   // serializes passwordHash, mfaSecret
};
```

**Checklist:**
- [ ] Props returned from `getServerSideProps` strip sensitive fields explicitly (don't rely on TS types - they are
      erased at runtime)
- [ ] Auth check inside `getServerSideProps` for protected pages (cookies parsed, session verified)
- [ ] Errors caught and rewritten to generic messages; never `props: { error: err.message }` with internal details

## 7. Image Optimization (`next/image`)

**Red Flags:**
```js
// VULNERABLE - permissive remotePatterns (or domains), no SSRF guard
module.exports = { images: { remotePatterns: [{ protocol: "https", hostname: "**" }] } };
```

**Checklist:**
- [ ] `images.remotePatterns` / `images.domains` is an explicit allowlist of upstreams
- [ ] No `**` wildcard hostname (Next 14+ deprecates `domains`; use `remotePatterns`)
- [ ] Built-in image optimizer is the SSRF-relevant surface - upstream URLs are server-fetched; allowlist constrains
      reach
- [ ] `dangerouslyAllowSVG: false` (default) unless SVG sanitization is in place

## 8. Rewrites / Redirects / Middleware Routing

**Red Flags:**
```js
// VULNERABLE - rewrite to user-controlled URL (open redirect / SSRF on server-side rewrite)
async rewrites() {
  return [{ source: "/proxy/:path*", destination: "https://:path*" }];
}
```

**Checklist:**
- [ ] Rewrites / redirects do not interpolate user input into the destination URL
- [ ] Server-side `redirect()` (in route handlers, server actions) validates target is internal (relative path
      starting with `/`, no `//`, no `://`)

## 9. Cache / Tags / `revalidatePath`

**Checklist:**
- [ ] `revalidatePath` / `revalidateTag` requires auth on the trigger endpoint (otherwise unauth'd cache poisoning is
      possible if cache key includes user data)
- [ ] `cache: "no-store"` for fetches that contain auth-sensitive data; do not cache user-specific responses at the
      route level

## 10. Prototype Pollution via `qs`

**Checklist:**
- [ ] Next does not parse query strings with `qs` for `searchParams` (uses `URLSearchParams`), but third-party body
      parsers might. See `lang-pitfalls.md` for the broader pattern.

## References

- Next.js security: https://nextjs.org/docs/app/building-your-application/authentication
- Server actions security: https://nextjs.org/blog/security-nextjs-server-components-actions
