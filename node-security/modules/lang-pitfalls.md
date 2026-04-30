---
name: Node/JS Language-Specific Pitfalls
description: Prototype pollution, regex DoS, child_process, vm escape, ESM/CJS confusion, async race in middleware
applies_to:
  - any
version: 1
last_updated: 2026-04-30
---

# Node/JS Language-Specific Pitfalls

Always-on. Catches Node and JS-specific footguns that do not fit a single OWASP category.

## 1. Prototype Pollution

**Red Flags:**
```js
// VULNERABLE - lodash.merge / .merge / .set with user input (older versions, or any custom impl)
const _ = require("lodash");
_.merge({}, req.body);                                          // lodash <4.17.20 vulnerable
_.set({}, req.body.path, req.body.value);                       // path can be "__proto__.polluted"

// VULNERABLE - hand-rolled merge / setter
function setDeep(obj, path, value) {
  const keys = path.split(".");
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) cur = cur[keys[i]] ??= {};
  cur[keys.at(-1)] = value;                                     // path "__proto__.x" pollutes Object.prototype
}

// VULNERABLE - Express qs parser produces nested objects from query strings
// app.get("/x?foo[__proto__][polluted]=1") -> req.query = { foo: {} } with polluted prototype
// any later `if (someObj.polluted)` returns true

// SAFE
function setDeep(obj, path, value) {
  const keys = path.split(".");
  for (const k of keys) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      throw new Error("forbidden key");
    }
  }
  // ... proceed
}

// SAFE - Object.create(null) for user-controlled key maps
const map = Object.create(null);
map[userKey] = value;                                           // no Object.prototype to pollute

// SAFE - freeze the prototype globally (hardened deployments)
Object.freeze(Object.prototype);
```

**Attack Scenario:** attacker posts `{"__proto__": {"isAdmin": true}}`; later code `if (user.isAdmin)` on a fresh user
object returns true via prototype chain.

**Checklist:**
- [ ] Lodash pinned ≥4.17.21; `merge`/`mergeWith`/`defaultsDeep`/`set`/`setWith`/`zipObjectDeep` audited
- [ ] `mixin-deep` ≥1.3.2, `merge-deep` ≥3.0.3, `set-value` ≥4.0.1, `dot-prop` ≥6.0.1, `unset-value` ≥2.0.1,
      `deep-extend` ≥0.5.1, `object-path` ≥0.11.5
- [ ] Custom merge / clone / setter functions reject keys `__proto__`, `constructor`, `prototype` (or use
      `Object.create(null)` maps for user-controlled data)
- [ ] `JSON.parse` reviver does not assign to `__proto__` keys
- [ ] `Object.assign(target, req.body)` reviewed - if `target` is later treated as authority, attacker controls fields
- [ ] Express `qs` parser is on by default (`req.query` and `req.body` from `express.urlencoded`); do not pass `req.query`
      directly to merge/set helpers. Disable nested parsing if not needed: `app.set("query parser", "simple")`
- [ ] Schema validation (zod/joi/ajv) applied *before* any deep merge / set with user input
- [ ] `Object.freeze(Object.prototype)` considered for hardened deployments (may break poorly-written deps; test)

## 2. Regex DoS (ReDoS)

**Red Flags:**
```js
// VULNERABLE - catastrophic backtracking
/^(a+)+$/.test(input);
/^(\w+\s?)*$/.test(input);
/^([a-zA-Z0-9]+)*@/.test(input);

// VULNERABLE - user-controlled pattern
new RegExp(req.query.pattern).test(target);

// VULNERABLE - long input + complex regex (event-loop block)
/^(.*?)+$/.test(longString);
```

**Checklist:**
- [ ] No user input as regex *pattern* (only as input to a static pattern)
- [ ] Nested quantifiers (`(a+)+`, `(a*)*`, `(.+)*`) audited
- [ ] Long input + complex regex pairs cap input length before matching
- [ ] For untrusted regex evaluation: `node-re2` or `re2-wasm` (linear time, no backtracking)
- [ ] Pinned versions of validators with prior ReDoS CVEs: `validator` ≥13.7.0, `ms` ≥2.1.3, `moment` deprecated -
      switch to `dayjs` or `luxon`, `marked` ≥4.0.10
- [ ] Event-loop sanity test: regex against 100KB of pathological input completes in <100ms

## 3. child_process / Command Injection

**Red Flags:**
```js
// VULNERABLE
const { exec, execSync } = require("child_process");
exec(`convert ${filename} out.png`);                            // template literal in exec
execSync("git clone " + repoUrl);
spawn("sh", ["-c", `tar -xf ${file}`]);                         // shell wrapper with interpolation
spawn(cmd, args, { shell: true });                              // shell:true with interpolation in cmd/args

// SAFE
const { execFile, spawn } = require("child_process");
execFile("convert", [filename, "out.png"]);                     // argv form, no shell
spawn("git", ["clone", repoUrl]);                               // shell:false (default)
```

**Checklist:**
- [ ] Grep `child_process.exec(`, `execSync(`, `spawn(.*shell:\s*true`, `spawn\(\s*"sh"`, `spawn\(\s*"bash"`
- [ ] Every hit uses static command or argv array form; no template literals or `+` concat with user input
- [ ] `shell: true` only with static command strings, never with interpolated user input
- [ ] PATH for spawned processes restricted via `env:` option (do not inherit attacker-controllable PATH)
- [ ] Tools spawned: `git`, `convert`/ImageMagick, `ffmpeg`, `pdftk`, `tar`, `unzip`, `youtube-dl`/`yt-dlp` use argv form
- [ ] Filename / argument values that could start with `-` are prefixed with `--` separator (`["git", "clone", "--",
      url]`) to prevent flag injection

## 4. vm Module / "Sandbox" Escape

**Red Flags:**
```js
// VULNERABLE - vm is NOT a security boundary
const vm = require("node:vm");
vm.runInNewContext(req.body.code, { /* ... */ });               // documented escape via constructor chain
new vm.Script(req.body.code).runInContext(ctx);

// VULNERABLE - vm2 / isolated-vm with wrong assumptions
// vm2 is unmaintained and has had multiple sandbox escapes (2023-2024 CVEs)
const { VM } = require("vm2");
new VM().run(req.body.code);
```

**Attack Scenario:** attacker crafts code that walks `this.constructor.constructor("return process")()` to escape vm
context; gains full Node access.

**Checklist:**
- [ ] No `vm.runInNewContext`, `vm.runInContext`, `new vm.Script(...).runIn*` on user input
- [ ] `vm2` package not used (unmaintained, multiple unfixed escapes - migrate to `isolated-vm` or process isolation)
- [ ] If user-supplied code execution is a feature: run in a *separate process* (worker_threads with limited globals,
      child_process with seccomp/AppArmor, or remote sandbox like Deno/Cloudflare Workers)
- [ ] `eval`, `new Function(...)`, `Function.constructor` patterns flagged separately - same root issue

## 5. require() / dynamic import with user input

**Red Flags:**
```js
// VULNERABLE - load module by user-controlled name
require(`./plugins/${req.query.name}`);                         // ../etc/passwd or path that triggers prototype side effect
import(req.body.module);                                        // ditto for ESM
```

**Checklist:**
- [ ] Grep for `require(` and `import(` with template literals or variables; verify input is from a static allowlist,
      not raw user input
- [ ] Plugin systems use an explicit registry (`const PLUGINS = { foo, bar }; PLUGINS[name]`) with prototype guards
- [ ] `require.resolve` paths likewise validated

## 6. ESM / CJS Confusion

**Red Flags:**
```js
// VULNERABLE - top-level await before auth setup
// ESM file
const config = await loadConfig();                              // OK
const app = express();
app.use(authMiddleware);                                        // races with route registration in some bundlers

// VULNERABLE - dynamic import of CJS package returns { default: ... }; missing .default leaves auth check undefined
import jwt from "jsonwebtoken";                                 // works
const jwt2 = await import("jsonwebtoken");                      // jwt2.verify is undefined - jwt2.default.verify
```

**Checklist:**
- [ ] Authentication middleware mounted before any route registration (audit ESM module init order)
- [ ] Dynamic `import()` of CJS modules accesses `.default` correctly; check `package.json` `type: "module"` consistency
- [ ] `package.json` `exports` field reviewed - `condition` mismatches (browser vs node vs default) can swap
      implementations between dev and prod
- [ ] Bundler resolution: ensure server code is not accidentally bundled with browser shims (jsonwebtoken, bcrypt
      replaced with no-op browser stubs is a real footgun)

## 7. Async Race / Middleware Order

**Red Flags:**
```js
// VULNERABLE - error not awaited; goes to unhandledRejection
app.post("/charge", (req, res) => {
  service.chargeCard(req.user.id);                              // unhandled if rejects
  res.sendStatus(200);
});

// VULNERABLE - middleware order leaves routes unprotected
app.get("/admin", adminHandler);                                // mounted before authMiddleware below
app.use(authMiddleware);                                        // too late

// VULNERABLE - shared mutable module state
let currentUser;                                                // global, multi-request races
app.use((req, _res, next) => { currentUser = req.user; next(); });
```

**Checklist:**
- [ ] All async route handlers either `await` everything or use `express-async-errors` / `next(err)` propagation;
      Express 5 handles async natively, Express 4 does not
- [ ] No top-level `let` / `var` storing per-request data outside `req` / `res` (no `currentUser` globals)
- [ ] Auth/CSRF middleware mounted before any protected routes; routes registered in order
- [ ] `process.on("unhandledRejection")` does NOT swallow errors silently - log + exit

## 8. JSON.parse and JSON Pollution

**Red Flags:**
```js
// VULNERABLE - JSON.parse with reviver that accepts attacker keys
JSON.parse(body, (k, v) => { obj[k] = v; return v; });          // populates obj with __proto__

// VULNERABLE - secondary parsing of trusted-looking JSON
const data = JSON.parse(req.body);
const merged = _.merge({}, data);                               // see Prototype Pollution

// SAFE
const data = JSON.parse(req.body);
const Schema = z.object({ name: z.string() });
const validated = Schema.parse(data);                           // strips unknown keys
```

**Checklist:**
- [ ] JSON revivers (when used) reject `__proto__`, `constructor`, `prototype` keys
- [ ] Parsed JSON validated by schema before use - especially before passing to ORM / merge / setter helpers

## References

- Prototype Pollution: https://github.com/HoLyVieR/prototype-pollution-nsec18
- vm escape (CVE-2023-37466 vm2): https://github.com/patriksimek/vm2/security/advisories
- Node.js child_process docs: https://nodejs.org/api/child_process.html
