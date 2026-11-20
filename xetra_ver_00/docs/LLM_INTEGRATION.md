# LLM Integration

## The hard boundary, stated once, enforced everywhere

ARTEX's LLM calls **decide the next attack step**. XETRA's LLM calls can only ever **draft a sentence a human reads afterward**. This isn't a tone choice — it's a structural guarantee:

- There is no code path from any LLM adapter method back into `HuntAgent`, `HardenAgent`, `RespondAgent`, or `RecoverAgent`. Those four only ever consume facts from BAS/SIEM/SOAR/EDR adapters.
- `LLMAdapter` (see `xetra/adapters/llm/base.py`) exposes exactly two methods, both named for what they are: `summarize_cycle` and `draft_remediation_note`. Both return `DraftText`, which carries `advisory_only: True` as a field that cannot be set to `False`.
- The only place LLM output lands is an `analyst_summary` block in ATTEST's evidence JSON, always paired with a disclaimer and the raw factual `summary` block it was drafted from (so a reviewer can check the draft against the facts in seconds).
- Disabled by default (`llm.provider: none`). Nothing about running XETRA requires an LLM.

This maps directly onto the governance model good AI-assisted-ops programs use (per the industry pattern reflected in XETRA's own design and documented in `README.md`): triage/drafting is a fine place for AI assistance; release authority, risk acceptance, and disclosure decisions stay with accountable people. HARDEN's remediation items and RESPOND's playbook triggers are decided entirely by HUNT's factual results — never by anything an LLM says.

## Setup

### Option 1 — mock (default exploration, zero API calls)
```yaml
llm:
  provider: mock
```
Runs today, no key needed, deterministic templated text so you can see the `analyst_summary` field's shape before going live.

### Option 2 — Anthropic Claude
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```
```yaml
llm:
  provider: anthropic
  options:
    model: "<a current model ID — check https://docs.anthropic.com/en/docs/about-claude/models>"
```
XETRA deliberately ships no default model string — model IDs change, and silently assuming one risks silently calling a deprecated or wrong model. Pick a current one from Anthropic's docs.

### Option 3 — OpenAI
```bash
export OPENAI_API_KEY=sk-...
```
```yaml
llm:
  provider: openai
  options:
    model: "<a current model ID — check https://platform.openai.com/docs/models>"
```

## What gets sent to the LLM

Only already-computed, already-factual XETRA data: the `summary` dict (counts — techniques tested, gaps found, etc.) for `summarize_cycle`, and one finding's technique ID / stratum / outcome for `draft_remediation_note`. Raw target hostnames, credentials, or scope details are never included in either prompt — review `agents/attest.py` and the two `*_llm.py` adapters to confirm this for your own compliance sign-off; don't take the claim on faith.

## Review requirement

Treat `analyst_summary.text` exactly like a junior analyst's first draft: useful starting material, never a finished artifact. Before it goes into a filing, a board update, or a certification evidence package, a named human reads it against the `summary` block it was drafted from and either approves or edits it. The `disclaimer` field in the evidence JSON exists so this requirement travels with the data, not just with this doc.
