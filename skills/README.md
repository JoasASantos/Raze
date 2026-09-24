# Raze as a skill

`skills/raze/SKILL.md` is a Claude Code / agent **skill** — same pattern as the
TypeSafe System One skill: it does not run the model, it teaches an agent *when
and how* to use Raze (the CLI + library) for offensive-security decisions.

## Install

Copy the skill into a skills directory the harness scans:

```bash
# user-level (Claude Code)
mkdir -p ~/.claude/skills && cp -r skills/raze ~/.claude/skills/raze

# or project-level
mkdir -p .claude/skills && cp -r skills/raze .claude/skills/raze
```

Then `pip install -e .` (optionally `.[all]` for provider SDKs) so the `raze` CLI
is on PATH. The agent will surface the `raze` skill when a task involves
offensive-security triage, prioritization, CVSS/CWE grounding, attack chaining, or
adaptive attack-path scoring.

A skill is portable: the same `SKILL.md` works wherever the harness loads skills
(Claude Code, and other agents that read the SKILL.md frontmatter contract).
