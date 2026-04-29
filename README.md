# skills

Collection of Claude Code skills for security review and related engineering tasks.

Each skill is a self-contained directory with a `SKILL.md` (the agent contract), a `README.md` (human
overview), and any supporting modules or tools.

## Available Skills

| Skill                              | Purpose                                                                    |
|------------------------------------|----------------------------------------------------------------------------|
| [`py-security`](./py-security)     | OWASP Top 10 vulnerability assessment for Python projects                  |

## Installation

Claude Code discovers skills under `~/.claude/skills/` (user-global) or `.claude/skills/` inside a
project (project-local). This repo is a source of truth; symlink the skills you want into the discovery
path.

**User-global (available in every project):**

```bash
mkdir -p ~/.claude/skills
ln -s "$(pwd)/py-security" ~/.claude/skills/py-security
```

**Project-local (one repo only):**

```bash
mkdir -p /path/to/target-repo/.claude/skills
ln -s "$(pwd)/py-security" /path/to/target-repo/.claude/skills/py-security
```

Verify discovery from inside an interactive Claude Code session by listing skills, or run a headless
probe (see below).

## Invoking a Skill

### Interactive

Inside a Claude Code session, reference the skill by name in your prompt
("use the py-security skill to review the auth module"). Claude loads `SKILL.md` and follows the
contract. The skill will ask for scope, focus, and prior context before scanning.

### Headless (CLI)

Use `claude -p` for non-interactive runs. The skill detects the absence of an interactive prompt and
follows its `Headless Mode` section.

```bash
# Mode B - diff-only (skill diffs against origin/main itself)
claude -p "Run py-security review on this branch" \
  --allowed-tools "Read,Bash,Grep,Glob"

# Mode A - explicit file list
claude -p "Use py-security skill. Review: app/api/users.py app/auth/jwt.py" \
  --allowed-tools "Read,Bash,Grep,Glob"
```

### Headless (Agent tool from another session)

A coordinator agent can spawn a subagent that runs the skill:

```
Agent({
  subagent_type: "general-purpose",
  description: "py-security review",
  prompt: "Use the py-security skill in headless mode. Review files X, Y, Z. Report findings only."
})
```

### CI / GitHub Actions

Wrap the headless CLI call in a workflow that runs on PR. Post the findings as a PR comment or fail the
build on Critical/High findings. Pin `--allowed-tools` to read-only tools so the skill cannot edit code
even if instructed to.

## Adding a Skill

1. Create a new top-level directory: `<skill-name>/`.
2. Add `SKILL.md` with frontmatter (`name`, `description`, `version`, `last_updated`) and the agent
   contract.
3. Add `README.md` with a human-facing overview.
4. Add an entry to the table above.
