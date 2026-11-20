# QUICKSTART

Follow these steps in order. Each one tells you exactly what you should see before moving to the next — if you don't see it, stop and fix it there; don't continue.

## 1. Install

```bash
pip install -e .
```
**You should see:** no errors, ends with `Successfully installed xetra-0.1.0`.

## 2. Create your config — guided, not hand-edited YAML

```bash
python -m xetra.cli init --config config/config.yaml
```
**You should see:** a prompt for each of BAS / SIEM / SOAR / EDR / LLM (press Enter to accept the safe `mock`/`none` default for all of them at this stage), then a summary of exactly which environment variables you'd need for whatever you picked (none, if you took all the defaults), then `doctor` runs automatically and shows the same checks as step 3 below.

(If you'd rather skip prompts entirely: `python -m xetra.cli init --config config/config.yaml --non-interactive` writes an all-mock config silently.)

## 3. Run the doctor

```bash
python -m xetra.cli doctor --config config/config.yaml
```
**You should see:** a list of checks, each `✅ PASS` or `⚠️ WARN`, zero `❌ FAIL`. Default config is all-mock, so four `WARN`s about mock mode are expected and fine at this stage. **If you see any `❌ FAIL`, stop and apply the `→ Fix:` line shown before continuing.**

## 4. Run one cycle

```bash
python -m xetra.cli run --config config/config.yaml --label first-run
```
**You should see:** log lines for HUNT → HARDEN → RESPOND → RECOVER → ATTEST, ending with `Evidence package written to: evidence_output/...json`.

## 5. Check status

```bash
python -m xetra.cli status --config config/config.yaml
```
**You should see:** `Last cycle: first-run`, a mode line (`⚠️ MOCK` at this stage — expected), and counts for techniques tested / gaps found / recoveries.

## 6. Open the dashboard

```bash
python -m xetra.cli serve --config config/config.yaml
```
Then open **http://localhost:8420**.

**You should see, top to bottom, in this order:**
1. An orange **MOCK MODE** banner (expected — you haven't configured a live adapter yet)
2. Five summary cards (techniques tested, gaps found, etc.) matching what `status` printed
3. A "Coverage by Stratum" bar for each stratum that had findings
4. An "Adapter Configuration" grid — all four should read `mock`
5. A trend chart (one data point so far)
6. A filterable findings table

If any of these six are missing or blank, something's wrong — don't proceed to a live config until this view is fully populated from mock data.

## 7. (Optional) Run everything in Docker instead of steps 1–6

```bash
./up
```
**You should see:** `Dashboard: http://localhost:8420` printed at the end. Same dashboard, same checks — this just runs it in containers with a 5-minute scheduler instead of manual commands.

## 8. Go live (only after 1–7 are all green)

Read `docs/GOING_LIVE.md` fully before touching this step. Do not skip the doctor check:

```bash
# edit config.yaml: set providers + scope.authorized_by + scope.targets
export ATTACKIQ_API_TOKEN=...   # etc., per docs/GOING_LIVE.md
python -m xetra.cli doctor --config config/config.yaml
```
**You should see:** `✅ PASS` on every adapter line and on `OVERALL MODE`. If you see even one `⚠️ WARN` on an adapter line, that category is still mock — the resulting evidence will have `mock_mode: true` and is not usable for certification.

Only once `doctor` is fully green should you run a cycle you intend to use as real evidence.

## If you get stuck

- `doctor` failing on something not covered above → the `→ Fix:` line it prints is the authoritative next step.
- Dashboard shows "No server detected" → confirm `serve` is actually running and you're hitting the right port.
- Dashboard shows stale-data red banner → the scheduler (cron loop or `xetra-cycle` container) has stopped; check its logs.
- Anything else → `docs/ARCHITECTURE.md` for how the pieces fit together, `docs/CONTROL_MAPPING.md` for what evidence maps to which certification, `docs/LLM_INTEGRATION.md` if you've enabled the optional LLM summary.
