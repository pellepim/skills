# gitleaks

Detects committed secrets (API keys, tokens, private keys) in git history and working tree.

## Install

```bash
brew install gitleaks
# or
docker run --rm -v "$(pwd):/path" zricethezav/gitleaks:latest detect --source=/path
```

## Run

```bash
# Working tree + uncommitted changes
gitleaks detect --no-git -v

# Full git history (slower, run pre-merge or in CI nightly)
gitleaks detect -v

# Only changes in this branch vs main
gitleaks detect --log-opts="origin/main..HEAD" -v
```

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

## When a secret is found

1. **Rotate immediately.** Removing the commit does not revoke the credential. Treat any committed
   secret as compromised.
2. Rewrite history (`git filter-repo` or `BFG`) only after rotation, and only if the secret has
   not yet been pulled by others.
3. Add the leaked-secret pattern to `.gitleaks.toml` allowlist only if it is a documented test
   fixture / example value.

## Configuration

`.gitleaks.toml` at repo root supports custom rules and allowlists. Add internal-secret prefixes
(e.g. `pl_live_`, `acme_prod_`) as custom rules so the scanner catches them even when generic
rules miss.

## Common JS/TS hot spots

- `.env`, `.env.local`, `.env.production` accidentally committed
- API keys hardcoded in `next.config.js`, `vite.config.ts`, `webpack.config.js`
- `process.env.SECRET = "..."` defaults in test files that get bundled
- `package.json` `scripts` with inline tokens (`"deploy": "vercel --token=..."`)
- Built artifacts under `dist/` / `build/` containing inlined env vars from a misconfigured
  bundler (Vite's `define`, webpack `DefinePlugin`)
