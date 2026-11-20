# XETRA

**ARTEX, reversed, is XETRA.**

XETRA is a continuous, evidence-generating control-validation orchestrator built as the structural inverse of [ARTEX](https://www.ic3.gov/) — the autonomous offensive agent framework described in FBI FLASH-20261113-001 (13 Nov 2026, TLP:CLEAR). Where ARTEX chains reconnaissance → exploitation → persistence → privilege escalation → lateral movement → exfiltration → C2 into a single breach, XETRA chains **HUNT → HARDEN → RESPOND → RECOVER → ATTEST** into a single, repeatable proof that each of those techniques is caught, contained, and recoverable — across the same 7 strata (infrastructure/network, service, system, protocol, algorithm, software, hardware) that ARTEX attacks.

**→ New here? Follow `QUICKSTART.md` step by step — it tells you exactly what to expect at each step, so you're never guessing whether something worked.**

```
pip install -e .
python -m xetra.cli init --config config/config.yaml     # guided setup — asks what to use, writes config, runs doctor for you
python -m xetra.cli run --config config/config.yaml --label first-run
python -m xetra.cli status --config config/config.yaml   # what just happened, at a glance
python -m xetra.cli serve --config config/config.yaml    # dashboard at http://localhost:8420
```

Runs immediately, with **zero credentials and zero external calls**, against deterministic mock data. Nothing in this repo touches a live system unless you explicitly configure a licensed adapter (see **Going Live**, below) — and `doctor` will tell you, explicitly, whether you're still in mock mode before you do anything with the results.

## CLI Commands

| Command | What it does |
|---|---|
| `xetra init --config ...` | **Start here.** Guided wizard: asks what BAS/SIEM/SOAR/EDR/LLM to use, writes `config.yaml`, prints exactly which env vars you need for what you picked, then runs `doctor` automatically so you see the result immediately. Add `--non-interactive` for an all-mock config with no prompts. |
| `xetra doctor --config ...` | Pre-flight check: config validity, adapter configuration state (mock vs. live), TTP library integrity, scope sanity. Reports PASS/WARN/FAIL with an explicit fix for each issue. Exit code 0 only if there are zero FAILs. |
| `xetra run --config ...` | Runs one full HUNT→HARDEN→RESPOND→RECOVER→ATTEST cycle (optionally one stratum only — the dashboard's per-stratum retest button uses this). |
| `xetra status --config ...` | What's true right now, in one screen: last cycle time + staleness, mode (mock/live per category), open-gap count. |
| `xetra serve --config ...` | Starts the dashboard at `http://localhost:8420` — Configuration panel (where everything is set, at a glance), per-stratum drill-down with a "re-test this stratum" button, trend chart, full findings table. Pass `--config` to enable the "Run cycle now" / per-stratum buttons. |
| `xetra list-ttps --config ...` | Lists every technique XETRA validates. |

---

## What this is — and isn't

**Is:**
- A real, working Python orchestrator: five agents, pluggable adapters, a TTP library, a CLI, tests, CI.
- A control-validation layer that sits *on top of* licensed security products you already own or can license (BAS, SIEM, SOAR, EDR), asking them to do what they're built and supported to do.
- A certification-evidence generator: every run produces a JSON package cross-walked to SOC 2, ISO 27001, PCI DSS v4.0, NIST CSF 2.0, FedRAMP, NYDFS §500, and NY MTL (`docs/CONTROL_MAPPING.md`).

**Isn't:**
- Not a fork, wrapper, or port of ARTEX. No exploitation logic exists anywhere in this codebase — not in the mock adapters (deterministic simulated outcomes), not in the "live" adapters (which only call each vendor's own documented, licensed scenario/test API; the vendor's platform owns the actual technique implementation).
- Not something that runs against a target without configuration. Every live adapter raises a clear `RuntimeError` naming exactly what's missing rather than silently doing anything.
- Not a replacement for a licensed BAS/SIEM/SOAR/EDR platform — it's the glue that runs them on a schedule and turns their output into one coherent, auditable cycle.

---

## Architecture

See `docs/ARCHITECTURE.md` for the full diagram and design rationale. Summary:

| Agent | Inverse of (ARTEX) | What it does |
|---|---|---|
| **HUNT** | recon + exploit agents | Runs each ATT&CK-mapped technique via your licensed BAS platform; checks your SIEM for an alert |
| **HARDEN** | persistence + privesc agents | Turns every gap into a `RemediationItem`, flagged for human approval |
| **RESPOND** | lateral movement + C2 agents | Triggers a named SOAR playbook (isolate/revoke/rotate/block) |
| **RECOVER** | collection + exfil agents | Re-runs HUNT on the remediated technique to confirm the gap closed |
| **ATTEST** | (ARTEX leaves forensic noise; XETRA leaves evidence by design) | Packages the full cycle as certification-ready JSON |

```
xetra/
├── xetra/
│   ├── orchestrator.py        # wires config -> adapters -> agents, runs one cycle
│   ├── cli.py                 # `xetra run`, `xetra list-ttps`, `xetra serve`
│   ├── server.py              # dashboard web server (stdlib only)
│   ├── agents/                # hunt.py, harden.py, respond.py, recover.py, attest.py
│   ├── adapters/
│   │   ├── bas/      # base, mock, attackiq, pentera, safebreach, cymulate
│   │   ├── siem/     # base, mock, splunk, sentinel, elastic
│   │   ├── soar/     # base, mock, tines, xsoar
│   │   └── edr/      # base, mock, crowdstrike, defender
│   └── ttp_library/
│       ├── artex_ttps.yaml         # core FBI-advisory ARTEX kill chain
│       └── attack_enterprise.yaml  # extended full-ATT&CK-Enterprise coverage
├── detections/           # Sigma rules (open standard)
├── dashboard/index.html  # offline evidence visualizer
├── docker/               # Dockerfile + compose, one-command demo
├── config/config.example.yaml
├── docs/ (ARCHITECTURE, CONTROL_MAPPING, GOING_LIVE) + mkdocs.yml
├── tests/
└── .github/workflows/ci.yml
```

---

## The TTP Library

`xetra/ttp_library/artex_ttps.yaml` encodes every phase of the ARTEX kill chain from the FBI advisory as MITRE ATT&CK technique IDs — the same identifiers every major BAS platform already uses to select its own pre-built, safe emulation module. Nothing beyond the ID, stratum, and expected control lives in this file. Run `python -m xetra.cli list-ttps` to see it.

| ARTEX phase | XETRA TTP entry | Stratum |
|---|---|---|
| Reconnaissance | `artex-recon-01` | infra_network |
| Initial Access | `artex-access-01` | service |
| Persistence | `artex-persist-01` | system |
| Privilege Escalation | `artex-privesc-01` | system |
| Internal Recon (incl. EDR-gap mapping) | `artex-discovery-01` | system |
| Lateral Movement | `artex-lateral-01` | system |
| Collection / Exfil Prep | `artex-collect-01` | service |
| Command and Control | `artex-c2-01` | protocol |
| LLM-API egress (ARTEX's signature fingerprint) | `artex-llm-egress-01` | infra_network |

The **program-level signature exercise**: replay this entire table as one BAS campaign, quarterly. Success = every phase caught before privilege escalation completes. This is the literal, direct antidote test.

A second file, `xetra/ttp_library/attack_enterprise.yaml`, extends coverage beyond the ARTEX-specific chain to the full MITRE ATT&CK Enterprise tactic set (Reconnaissance through Impact, 15 additional entries / ~55 additional technique IDs) — loaded by default alongside the core library (`include_extended_attack_library: true` in config). Run `python -m xetra.cli list-ttps` to see the combined total.

---

## Detection Content

`detections/` ships open-standard [Sigma](https://github.com/SigmaHQ/sigma) rules for five representative techniques (Kerberoasting, LSASS credential dumping, ransomware-style mass encryption, EDR/logging tamper attempts, and ARTEX's own LLM-API-egress fingerprint). Convert to your SIEM's native query language with `sigma-cli` and drop the result into the relevant adapter's `query_map`.

## Dashboard

`dashboard/index.html` is a self-contained, offline visual dashboard — drag an ATTEST evidence JSON file onto it and it renders summary cards, a per-stratum outcome chart, and the full findings table, entirely client-side (no server, no upload, no dependency beyond one CDN-hosted charting library).

## Docker

```
./up      # build + start → dashboard at http://localhost:8420
./down    # stop (evidence volume persists)
./clean   # stop + remove containers, image, evidence volume, local config
```

No `docker` typing required. `./up` starts two services sharing one evidence volume: `xetra-cycle` runs a mock HUNT→HARDEN→RESPOND→RECOVER→ATTEST cycle every 5 minutes, and `xetra-web` serves the dashboard — open **http://localhost:8420** and it auto-loads the latest cycle (polls every 10s, no manual file drag needed once the server's running; dragging a file in still works too, e.g. for a cycle you ran outside Docker). See `docker/README.md`.

## LLM Integration (optional, advisory-only)

XETRA can optionally use an LLM — Claude or GPT — to draft a plain-English executive summary of each cycle and draft (not finalize) remediation-ticket text. **The hard boundary: LLM output can only ever produce text for a human to review; it has no code path into HUNT, HARDEN, RESPOND, or RECOVER and cannot trigger any action.** This is the deliberate structural inverse of ARTEX's own LLM usage, where the LLM *is* the decision-maker for the next attack step.

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY for GPT
```
```yaml
# config.yaml
llm:
  provider: anthropic   # none (default) | mock | anthropic | openai
  options:
    model: "<current model ID from the provider's docs>"
```

Full detail, the exact prompts sent, and the review requirement before any LLM-drafted text is used: `docs/LLM_INTEGRATION.md`.

## Docs Site

`mkdocs.yml` + `docs/` form a ready-to-publish [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) site (`pip install mkdocs-material && mkdocs serve`).

---

## Going Live

Each stratum can go live independently. None of this is required to use XETRA in mock mode.

Five vendors per BAS/SIEM/SOAR/EDR category are wired in today — full detail and env-var names in `docs/GOING_LIVE.md`:

| Category | Providers wired in |
|---|---|
| BAS | AttackIQ, Pentera, SafeBreach, Cymulate |
| SIEM | Splunk, Microsoft Sentinel, Elastic |
| SOAR | Tines, Cortex XSOAR |
| EDR | CrowdStrike Falcon, Microsoft Defender for Endpoint |

**Before flipping anything to live:** fill in `scope.authorized_by` and `scope.targets` in `config.yaml` with your actual signed Rules of Engagement. BAS platforms enforce their own authorization model on top of this — XETRA's scope config is passed through to them, not a substitute for it.

Pluggable adapter interfaces (`adapters/*/base.py`) mean any additional vendor can be added as a sibling to the existing stubs without touching the orchestrator or agents — contributions welcome.

---

## Testing

```
pip install -r requirements-dev.txt
pytest tests/ -v
```

All tests run against mock adapters — no credentials, no network calls, no risk. CI (`.github/workflows/ci.yml`) runs this plus a full end-to-end CLI smoke test on every push, across Python 3.10–3.12.

---

## Certification Evidence

See `docs/CONTROL_MAPPING.md`. **Every evidence package has a top-level `mock_mode: true/false` field — check it before using anything downstream of it.** `mock_mode: true` means at least one adapter category (BAS/SIEM/SOAR/EDR) was simulated; the package is useful for testing the pipeline itself, never for an auditor. `xetra doctor` and the dashboard's mode banner both surface this before you can miss it.

Every ATTEST output is a JSON package: `mock_mode`, `adapter_modes` (per-category mock/live), findings, remediations, responses, recoveries, and a summary block — designed to be the machine-generated input to your audit evidence package, not a replacement for auditor review or management sign-off (consequential decisions stay with named humans throughout the loop — see `agents/harden.py` and `agents/attest.py` docstrings).

---

## Why "XETRA"

Not a backronym stretched to fit — reverse the five letters of ARTEX and you get XETRA. The name *is* the thesis: everything ARTEX automates toward compromise, XETRA automates toward proof that compromise doesn't land.

## License

MIT — see `LICENSE`.

## Responsible Use

This project automates licensed, authorized security-validation tooling. It does not contain, depend on, or interoperate with ARTEX or any unlicensed offensive framework. Contributions that add exploitation logic rather than orchestration of a licensed vendor's own API will not be accepted.
