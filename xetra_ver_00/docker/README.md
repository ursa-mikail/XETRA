# Docker Demo

```
cp ../config/config.example.yaml ../config/config.yaml
docker compose up --build
```

(or just `../up` from the repo root — same thing, no `docker` typing needed)

Two services, one shared evidence volume:

- **xetra-cycle** — runs a full HUNT→HARDEN→RESPOND→RECOVER→ATTEST cycle every 5 minutes against mock adapters (zero credentials needed).
- **xetra-web** — serves the dashboard at **http://localhost:8420**, auto-polling `/api/evidence` every 10s so it picks up each new cycle without you doing anything.

Open http://localhost:8420 after `./up` — give it a few seconds for the first cycle to land. You can also still drag a `xetra-attest-*.json` file onto the dashboard manually (e.g. one produced by a run outside Docker).
