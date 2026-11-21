# AI summaries (optional)

**Setup → AI summaries.** Choose Claude or GPT, paste your key, press **Test connection**, choose a model from the list your account returns, **Save**.

## The boundary (enforced in code, covered by tests)

* The AI receives only counts XETRA already computed (techniques tested, gaps found…). Never credentials or raw target data.
* Its output is text in one field of the evidence package, `analyst_summary`, labelled advisory and requiring human review.
* There is **no code path** from the AI back into Hunt, Harden, Respond or Recover. It cannot start, stop or change anything.
* If the AI call fails, the cycle still completes; the package records `analyst_summary_error`.

This is the structural inverse of ARTEX, where the model chooses the next attack step.

## Troubleshooting

| Test result | Meaning |
|---|---|
| "refused these credentials (HTTP 401)" | Key wrong, revoked or from another project. Create a new one. |
| "Could not connect" | Network/proxy blocks the provider's API host. |
| "'x' is not available to it" | Pick from the dropdown — model access differs per key. |
