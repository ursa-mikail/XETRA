"""
Provider registry — the ONE place that says what each integration is,
what it needs, and where to get it.

The dashboard's Connections tab, the `xetra init` wizard, `xetra doctor`
and the docs are all generated from this table, so they can never
disagree with each other (they used to: three hand-copied env-var lists).

Field kinds:
  secret  -> stored in .xetra/secrets.env (chmod 600), never echoed back
  text    -> stored in config.yaml (not sensitive: URLs, IDs, model names)
"""
from __future__ import annotations

CATEGORIES = {
    "bas":  {"label": "Attack emulation (BAS)", "role": "Runs safe, vendor-owned attack simulations so XETRA can see what your defences catch.", "required": True},
    "siem": {"label": "Detection (SIEM)",       "role": "Confirms that each simulated technique actually raised an alert.", "required": True},
    "soar": {"label": "Response (SOAR)",        "role": "Runs your containment playbooks (isolate, revoke, rotate, block).", "required": True},
    "edr":  {"label": "Endpoint (EDR)",         "role": "Checks sensor coverage and host isolation.", "required": True},
    "llm":  {"label": "AI summaries (LLM)",     "role": "Optional. Drafts plain-English summaries for a human to review. Can never trigger an action.", "required": False},
}

def _f(env, label, kind="secret", help="", placeholder="", config_key=None, default=""):
    return {"env": env, "label": label, "kind": kind, "help": help,
            "placeholder": placeholder, "config_key": config_key or env.lower(), "default": default}

PROVIDERS: dict[str, dict[str, dict]] = {
    "bas": {
        "mock": {"label": "Simulated (no credentials)", "fields": [], "docs": "", "live": False,
                 "blurb": "Deterministic demo data. Safe, instant, but NOT audit evidence."},
        "attackiq": {"label": "AttackIQ", "live": True, "docs": "https://docs.attackiq.com/",
                     "blurb": "Needs an Assessment per technique, built in your AttackIQ console.",
                     "fields": [_f("ATTACKIQ_BASE_URL", "Tenant URL", "text", "e.g. https://acme.attackiq.com", "https://your-tenant.attackiq.com"),
                                _f("ATTACKIQ_API_TOKEN", "API token", help="AttackIQ console → Profile → API token")]},
        "pentera": {"label": "Pentera", "live": True, "docs": "https://pentera.io/",
                    "blurb": "Needs an action ID per technique, built in the Pentera console.",
                    "fields": [_f("PENTERA_BASE_URL", "Server URL", "text", placeholder="https://pentera.your-company.com"),
                               _f("PENTERA_API_KEY", "API key")]},
        "safebreach": {"label": "SafeBreach", "live": True, "docs": "https://help.safebreach.com/",
                       "blurb": "Needs a move/scenario ID per technique.",
                       "fields": [_f("SAFEBREACH_BASE_URL", "Console URL", "text", placeholder="https://your-account.safebreach.com"),
                                  _f("SAFEBREACH_API_KEY", "API key")]},
        "cymulate": {"label": "Cymulate", "live": True, "docs": "https://docs.cymulate.com/",
                     "blurb": "Needs a template ID per technique.",
                     "fields": [_f("CYMULATE_BASE_URL", "API URL", "text", default="https://api.cymulate.com"),
                                _f("CYMULATE_API_KEY", "API key")]},
    },
    "siem": {
        "mock": {"label": "Simulated (no credentials)", "fields": [], "docs": "", "live": False,
                 "blurb": "Deterministic demo data. Safe, instant, but NOT audit evidence."},
        "splunk": {"label": "Splunk", "live": True, "docs": "https://docs.splunk.com/",
                   "blurb": "Needs an SPL query per technique (start from detections/*.yml).",
                   "fields": [_f("SPLUNK_BASE_URL", "Management URL", "text", "Usually port 8089", "https://splunk.example.com:8089"),
                              _f("SPLUNK_TOKEN", "Auth token")]},
        "sentinel": {"label": "Microsoft Sentinel", "live": True, "docs": "https://learn.microsoft.com/azure/sentinel/",
                     "blurb": "Needs a KQL query per technique.",
                     "fields": [_f("SENTINEL_WORKSPACE_ID", "Log Analytics workspace ID", "text"),
                                _f("AZURE_TOKEN", "Azure bearer token")]},
        "elastic": {"label": "Elastic", "live": True, "docs": "https://www.elastic.co/guide/",
                    "blurb": "Needs an index + query per technique.",
                    "fields": [_f("ELASTIC_URL", "Elasticsearch URL", "text", placeholder="https://elastic.example.com:9200"),
                               _f("ELASTIC_API_KEY", "API key")]},
    },
    "soar": {
        "mock": {"label": "Simulated (no credentials)", "fields": [], "docs": "", "live": False,
                 "blurb": "Pretends playbooks ran. NOT audit evidence."},
        "tines": {"label": "Tines", "live": True, "docs": "https://www.tines.com/docs/",
                  "blurb": "Playbooks are webhook URLs you map in config.yaml (soar.options.webhook_map).",
                  "fields": [_f("TINES_TENANT_URL", "Tenant URL", "text", placeholder="https://your-tenant.tines.com"),
                             _f("TINES_API_TOKEN", "API token")]},
        "xsoar": {"label": "Cortex XSOAR", "live": True, "docs": "https://docs-cortex.paloaltonetworks.com/",
                  "blurb": "Maps each playbook name to an XSOAR playbook.",
                  "fields": [_f("XSOAR_BASE_URL", "Server URL", "text", placeholder="https://xsoar.example.com"),
                             _f("XSOAR_API_KEY", "API key")]},
    },
    "edr": {
        "mock": {"label": "Simulated (no credentials)", "fields": [], "docs": "", "live": False,
                 "blurb": "Fake fleet of 100 hosts. NOT audit evidence."},
        "crowdstrike": {"label": "CrowdStrike Falcon", "live": True, "docs": "https://falcon.crowdstrike.com/documentation",
                        "blurb": "API client needs Hosts: Read and Hosts: Write scopes.",
                        "fields": [_f("FALCON_BASE_URL", "API base URL", "text", "Use your cloud's URL (us-1, eu-1, …)", default="https://api.crowdstrike.com"),
                                   _f("FALCON_CLIENT_ID", "Client ID", "text"),
                                   _f("FALCON_CLIENT_SECRET", "Client secret")]},
        "defender": {"label": "Microsoft Defender for Endpoint", "live": True, "docs": "https://learn.microsoft.com/microsoft-365/security/defender-endpoint/",
                     "blurb": "Bearer token with Machine.Read.All and Machine.Isolate.",
                     "fields": [_f("DEFENDER_TOKEN", "Bearer token")]},
    },
    "llm": {
        "none": {"label": "Off (recommended to start)", "fields": [], "docs": "", "live": False,
                 "blurb": "No AI text. Everything else works exactly the same."},
        "mock": {"label": "Template text (no API call)", "fields": [], "docs": "", "live": False,
                 "blurb": "Fills the summary box with a fixed template so you can see where it appears."},
        "anthropic": {"label": "Claude (Anthropic)", "live": True, "docs": "https://docs.anthropic.com/en/docs/about-claude/models",
                      "blurb": "Paste a key, press Test, then pick a model from the list we fetch for you.",
                      "model_env": "ANTHROPIC_MODEL",
                      "fields": [_f("ANTHROPIC_API_KEY", "API key", help="console.anthropic.com → API keys. Starts with sk-ant-", placeholder="sk-ant-…")]},
        "openai": {"label": "GPT (OpenAI)", "live": True, "docs": "https://platform.openai.com/docs/models",
                   "blurb": "Paste a key, press Test, then pick a model from the list we fetch for you.",
                   "model_env": "OPENAI_MODEL",
                   "fields": [_f("OPENAI_API_KEY", "API key", help="platform.openai.com → API keys. Starts with sk-", placeholder="sk-…")]},
    },
}

# Every strata XETRA validates, in attack-surface order, with plain-English meaning.
STRATA = [
    {"id": "infra_network", "n": 1, "name": "Infrastructure / Network", "short": "Network",
     "blurb": "Cloud perimeter, exposed admin planes, VPN, DNS, routing."},
    {"id": "service", "n": 2, "name": "Service", "short": "Service",
     "blurb": "Web apps, APIs, databases, partner portals, CI/CD."},
    {"id": "system", "n": 3, "name": "System", "short": "System",
     "blurb": "Operating systems, Active Directory, endpoints, EDR coverage."},
    {"id": "protocol", "n": 4, "name": "Protocol", "short": "Protocol",
     "blurb": "SAML/OAuth, Kerberos, SMB, TLS, tunnelling."},
    {"id": "algorithm", "n": 5, "name": "Algorithm", "short": "Algorithm",
     "blurb": "Cryptography, key management, business logic."},
    {"id": "software", "n": 6, "name": "Software / Language", "short": "Software",
     "blurb": "Code bugs, dependencies, build pipeline integrity."},
    {"id": "hardware", "n": 7, "name": "Hardware", "short": "Hardware",
     "blurb": "Firmware, TPM/HSM, supply chain."},
]
STRATUM_IDS = [s["id"] for s in STRATA]


def env_names(category: str, provider: str) -> list[str]:
    p = PROVIDERS.get(category, {}).get(provider, {})
    names = [f["env"] for f in p.get("fields", [])]
    if p.get("model_env"):
        names.append(p["model_env"])
    return names


def public_catalog() -> dict:
    """JSON-safe catalog for the dashboard."""
    return {"categories": CATEGORIES, "providers": PROVIDERS, "strata": STRATA}
