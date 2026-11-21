# Going live

Use the dashboard: **Setup**. This page lists what each tool needs. (Generated from `xetra/providers.py`, which is also what Setup uses.)

Go one category at a time. After each: **Test connection → Save → run one stratum → check the Activity log**.

| Category | Tool | Fields |
|---|---|---|
| BAS | AttackIQ | `ATTACKIQ_BASE_URL`, `ATTACKIQ_API_TOKEN` + one Assessment per technique (`scope.attackiq_assessment_map`) |
| BAS | Pentera | `PENTERA_BASE_URL`, `PENTERA_API_KEY` |
| BAS | SafeBreach | `SAFEBREACH_BASE_URL`, `SAFEBREACH_API_KEY` |
| BAS | Cymulate | `CYMULATE_BASE_URL`, `CYMULATE_API_KEY` |
| SIEM | Splunk | `SPLUNK_BASE_URL` (management port), `SPLUNK_TOKEN` + an SPL query per technique (start from `detections/*.yml`) |
| SIEM | Sentinel | `SENTINEL_WORKSPACE_ID`, `AZURE_TOKEN` |
| SIEM | Elastic | `ELASTIC_URL`, `ELASTIC_API_KEY` |
| SOAR | Tines | `TINES_TENANT_URL`, `TINES_API_TOKEN` + `soar.options.webhook_map` |
| SOAR | Cortex XSOAR | `XSOAR_BASE_URL`, `XSOAR_API_KEY` |
| EDR | CrowdStrike | `FALCON_BASE_URL`, `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` |
| EDR | Defender | `DEFENDER_TOKEN` |
| LLM | Claude | `ANTHROPIC_API_KEY` (+ model, chosen from a fetched list) |
| LLM | GPT | `OPENAI_API_KEY` (+ model, chosen from a fetched list) |

Environment variables you set yourself always win over the values saved by the dashboard (so Docker/Kubernetes secrets keep working).

## Before the first live run

1. **Setup → Who authorised testing?** Record the person who signed your Rules of Engagement.
2. Leave **Controls → Allow real containment playbooks** **off**. Review what each playbook does first. While off, Respond records what it *would* have run.
3. Prefer **staging**. Your BAS tool enforces its own authorisation on top of XETRA's scope.
4. Some adapters (`not_tested` results) need per-technique mappings built in the vendor console. A missing mapping is reported as **couldn't test**, never as a pass.

## Not yet verified

Vendor adapters follow each vendor's public API documentation but have not been run against live tenants by the authors. Run one stratum and read the raw result (click a technique) before trusting a full cycle.
