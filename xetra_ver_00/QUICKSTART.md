# Quickstart

## 1. Install and open

```bash
pip install -e .
xetra start
```
**You should see:** a browser tab on http://localhost:8420 with an amber **Simulated data** badge and a card saying **Run your first check**. If the page doesn't open, go to that address yourself.

## 2. Run all 7 strata

Press **Run all 7 strata**. **You should see:** the top bar counting up, five stages lighting in turn, and every square on the Overview filling in. It takes about five seconds.

## 3. Look at one stratum

Click **System** in the left rail. **You should see:** its squares, a table of techniques with what your controls should do, and a **Re-test this stratum** button. Re-testing it leaves the other six alone.

## 4. Decide a gap

Open **Fix list → Approve fix**, enter your name. In simulated mode, press **Retest stratum** and the item turns **verified** by itself.

## 5. Connect real tools (when ready)

Open **Setup** and go top to bottom. For each tool: pick → paste → **Test connection** → **Save**. Switch one category at a time. Until all four core tools are live the badge stays amber and evidence is marked `mock_mode: true`.

For **AI summaries**, choose Claude or GPT, paste the key, press **Test connection**, then choose a model from the list it shows you.

## 6. Make it continuous

**Controls → Run automatically**. The next run time is always shown in the top bar. **Pause** stops everything instantly.

## If something looks wrong

| You see | Do this |
|---|---|
| "Can't reach XETRA" | Run `xetra start` again. |
| A red result under Test connection | Read the line under it — it names the fix. |
| Run buttons greyed out | Look at the top bar: you're paused or a run is in progress. |
| Not sure what's configured | `xetra doctor` (same checks as the bottom of Setup). |
