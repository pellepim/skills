# bandit

Python AST-based security linter from PyCQA. Catches common Python-specific footguns.

## Install

```bash
pip install bandit
# or, if using ruff (recommended — bandit rules are integrated as the S category):
pip install ruff
```

## Run

```bash
# Standalone bandit
bandit -r . -ll -x tests,migrations

# Equivalent via ruff (faster, same rule set)
ruff check --select=S --exclude=tests,migrations .
```

Flags:
- `-r .` — recurse from current directory
- `-ll` — only Medium+ severity, Medium+ confidence (filters noise)
- `-x` — exclude test/migration directories (high false-positive rate)

## Useful rule IDs to know

| ID   | Pattern                                    |
|------|--------------------------------------------|
| B102 | `exec`                                     |
| B201 | Flask `debug=True`                         |
| B301 | `pickle.loads`                             |
| B303 | MD5/SHA1                                   |
| B306 | `mktemp` (predictable temp file)           |
| B307 | `eval`                                     |
| B311 | `random` for security                      |
| B321 | FTP                                        |
| B324 | `hashlib.new` with weak algo               |
| B501 | `requests` with `verify=False`             |
| B506 | `yaml.load` without SafeLoader             |
| B602 | `subprocess` with `shell=True`             |
| B608 | hardcoded SQL string with format/concat    |

## Suppression

Per-line: `# nosec B602 — argv list is hardcoded, no user input`. Always include rule ID and reason.

## Exit codes

`bandit` exits non-zero on findings. Wire into CI as a warn (not block) initially; promote to block after baseline
triage.
