# Going Live, Stratum by Stratum

Each stratum's adapter can go live independently. All defaults are
`mock` — nothing below is required to use XETRA.

## BAS (HUNT's attack-emulation source)

| Provider | Env vars | Scope config |
|---|---|---|
| AttackIQ | `ATTACKIQ_BASE_URL`, `ATTACKIQ_API_TOKEN` | `scope.attackiq_assessment_map` |
| Pentera | `PENTERA_BASE_URL`, `PENTERA_API_KEY` | `scope.pentera_action_map` |
| SafeBreach | `SAFEBREACH_BASE_URL`, `SAFEBREACH_API_KEY` | `scope.safebreach_move_map` |
| Cymulate | `CYMULATE_API_KEY` | `scope.cymulate_attack_map` |

Each map is `attack_id -> <vendor's own scenario/action/move/template ID>`, built once inside that vendor's console against your authorized scope.

## SIEM (HUNT's detection-confirmation source)

| Provider | Env vars | Config |
|---|---|---|
| Splunk | `SPLUNK_BASE_URL`, `SPLUNK_TOKEN` | `siem.splunk.query_map` (SPL per technique) |
| Microsoft Sentinel | `SENTINEL_WORKSPACE_ID`, `AZURE_TOKEN` | `siem.sentinel.query_map` (KQL per technique) |
| Elastic | `ELASTIC_URL`, `ELASTIC_API_KEY` | `siem.elastic.query_map` (index + DSL per technique) |

Start from `detections/*.yml` (Sigma rules) and convert with `sigma-cli` to your platform's query language.

## SOAR (RESPOND's containment trigger)

| Provider | Env vars | Config |
|---|---|---|
| Tines | n/a (webhook URLs) | `soar.tines.webhook_map` |
| Cortex XSOAR | `XSOAR_BASE_URL`, `XSOAR_API_KEY` | `soar.xsoar.playbook_map` |

## EDR (HARDEN's coverage check, RECOVER's isolation)

| Provider | Env vars |
|---|---|
| CrowdStrike Falcon | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` |
| Microsoft Defender for Endpoint | `DEFENDER_TOKEN` |

## Before any live run

Fill `scope.authorized_by` and `scope.targets` in `config.yaml` with your actual signed Rules of Engagement. The licensed platform enforces its own authorization boundary on top of this — this config is passed through to it, never a substitute for it.
