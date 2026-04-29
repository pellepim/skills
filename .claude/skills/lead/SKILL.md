---
name: lead
description: Tech-lead backlog. Capture future improvements, triage them, surface follow-ups. Trigger on "/lead", "add to backlog", "follow up on", "what's next on the backlog", or after finishing work that has an obvious follow-up but the user does not want to schedule a remote agent.
version: 1
last_updated: 2026-04-29
---

# Lead - Backlog Maintainer

Acts as a lightweight tech-lead. Tracks future work that is too small for an issue tracker
but too large to keep only in conversation memory.

## Quick Reference

- **Reads:** `BACKLOG.md` (this skill's directory)
- **Writes:** `BACKLOG.md`
- **Can commit:** Only when user asks

## Storage

Single file: `.claude/skills/lead/BACKLOG.md` at repo root.

Each item is an H2 section. ID format `L-NNN`, zero-padded, monotonic. Never reuse IDs.

Section template:

```markdown
## L-NNN: <short title>

- Status: open | in-progress | blocked | done | dropped
- Priority: high | medium | low
- Created: YYYY-MM-DD
- Updated: YYYY-MM-DD
- Tags: comma, separated
- Owner: <name or unassigned>

<one paragraph: what + why. links if any.>

### Plan
- step
- step

### Notes
- YYYY-MM-DD: progress note
```

`Plan` and `Notes` are optional. Keep entries skimmable.

## Commands

User invokes via `/lead <verb> [args]`. If no verb, show summary + propose next action.

| Verb        | Action                                                                                |
|-------------|---------------------------------------------------------------------------------------|
| `add`       | Append new item. Ask for title if not given. Default Status=open, Priority=medium.    |
| `list`      | Show open + in-progress, sorted by Priority then Created. Skip done/dropped.          |
| `show <id>` | Print full section.                                                                   |
| `update <id>` | Change fields. Bump `Updated`. Append note to `### Notes`.                          |
| `start <id>` | Set Status=in-progress. Bump Updated.                                                |
| `block <id>` | Set Status=blocked. Append reason to Notes.                                          |
| `done <id>`  | Set Status=done. Bump Updated. Append closing note.                                  |
| `drop <id>`  | Set Status=dropped. Append reason.                                                   |
| `triage`     | Review all open items. Flag stale (Updated > 30d). Suggest priority changes.         |
| `pick`       | Recommend next item to work on. Highest Priority, oldest Created, not blocked.       |
| `archive`    | Move done/dropped older than 90 days to `BACKLOG-archive.md`.                        |

## Behaviors

### On add
1. Read `BACKLOG.md`. If missing, create with header.
2. Find max existing `L-NNN`. Increment.
3. Append new section. Set Created and Updated to today.
4. Confirm: "Added L-NNN: <title>".

### On follow-up trigger (no explicit command)
If user finishes work and the conversation surfaces an obvious follow-up that does not
warrant `/schedule`, offer one line: "Add to backlog as L-NNN-draft? <title>". Only
proactive if signal is strong (TODO left in code, deferred refactor, partial fix).

### On session start with stale items
If the user types `/lead` with no args and items have `Updated` older than 14 days while
Status=in-progress, list them as "stalled" with a one-line nudge.

### Idempotency
Multiple `add` calls with near-identical titles should be detected. Compare
case-insensitive title. If similar exists, ask: "L-NNN already covers this. Update
instead?".

## Editing rules

- Always read `BACKLOG.md` before writing.
- Use the Edit tool for changes to existing items. Use Write only for first creation.
- Never rewrite the whole file just to change one field.
- Bump `Updated` on every change to a section.
- Date format: ISO `YYYY-MM-DD`. Use today's date from system context.
- No en-dashes in prose.

## Reporting format

`/lead list` output:

```
Open (N)
  L-003 [high]   <title>           updated 2026-04-20  tags: security
  L-001 [medium] <title>           updated 2026-04-29
In progress (M)
  L-002 [high]   <title>           started 2026-04-25
```

`/lead pick` output: one item, one paragraph on why it is next, plus first concrete step.

## Out of scope

- Not a substitute for issue trackers on shared work. If user mentions Linear/Jira, ask
  whether item belongs there instead.
- Does not auto-execute work. Only tracks. To run an item, user starts a normal session.
- Does not schedule reminders. For time-based follow-ups, suggest `/schedule` instead.
