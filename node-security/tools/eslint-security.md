# eslint security plugins

JS/TS security lints. Three plugins worth combining; each catches different patterns.

## Install

```bash
npm i -D eslint \
  eslint-plugin-security \
  eslint-plugin-no-unsanitized \
  @typescript-eslint/eslint-plugin
```

## Config (flat config, ESLint ≥9)

```js
// eslint.config.js
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";

export default [
  security.configs.recommended,
  {
    plugins: { "no-unsanitized": noUnsanitized },
    rules: {
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
    },
  },
];
```

## Run

```bash
npx eslint --ext .js,.ts,.tsx .
# Diff-only (CI):
npx eslint $(git diff --name-only origin/main...HEAD | grep -E '\.(js|ts|tsx)$')
```

## Useful rule IDs

`eslint-plugin-security`:

| ID                                                | Pattern                                                  |
|---------------------------------------------------|----------------------------------------------------------|
| `security/detect-eval-with-expression`            | `eval(x)` where x is not a string literal                |
| `security/detect-non-literal-require`             | `require(x)` with non-literal                            |
| `security/detect-non-literal-fs-filename`         | `fs.readFile(x)` where x is not a literal                |
| `security/detect-child-process`                   | Any `child_process` import                               |
| `security/detect-unsafe-regex`                    | Catastrophic-backtracking patterns                       |
| `security/detect-buffer-noassert`                 | `Buffer` access with `noAssert: true`                    |
| `security/detect-pseudoRandomBytes`               | `crypto.pseudoRandomBytes`                               |
| `security/detect-disable-mustache-escape`         | Mustache `{{{ }}}`                                       |
| `security/detect-object-injection`                | Bracket access by user-controlled key (NOISY)            |

`eslint-plugin-no-unsanitized`:

| ID                                                | Pattern                                                  |
|---------------------------------------------------|----------------------------------------------------------|
| `no-unsanitized/method`                           | `insertAdjacentHTML`, `Range.createContextualFragment`   |
| `no-unsanitized/property`                         | `innerHTML`, `outerHTML`, `srcdoc`, `documentURI`        |

## Suppression

```js
// eslint-disable-next-line security/detect-object-injection -- key is from a static enum
const handler = handlers[opcode];
```

Always include the rule ID and a reason. PR review should reject suppressions without reasons.

## Notes

- `detect-object-injection` flags `obj[userKey]` patterns. It catches real prototype-pollution and
  type-confusion bugs but is noisy on internal lookup tables. Default to `"warn"`, or restrict
  with `overrides` to handler/middleware files.
- `detect-non-literal-fs-filename` catches path-traversal candidates but produces many false
  positives in code that uses `path.join`. Pair with manual review of every hit.
- For React/Vue templates, add `eslint-plugin-react` (`react/no-danger`) and
  `eslint-plugin-vue` (`vue/no-v-html`).
