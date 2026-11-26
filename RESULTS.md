# Results — real benchmark run

Numbers below come from an actual execution of `eval/run_benchmark.py`. Nothing
is estimated or hand-filled.

```bash
python -m eval.run_benchmark --out eval/results.json
```

| Field | Value |
| --- | --- |
| Run timestamp | 2026-11-23T00:54:58+0530 |
| Model | OpenAI-compatible chat model (name recorded in `eval/results.json`) |
| Backend | Any OpenAI-compatible chat-completions endpoint |
| Max iterations | 3 |
| Tasks | 10 |
| Errors | 0 |

---

## Headline metrics

| Metric | Value |
| --- | --- |
| **First-pass rate** | **80.0%** (8/10) |
| **Self-corrected pass rate** | **10.0%** (1/10) |
| **Final pass rate** | **90.0%** (9/10) |
| **Security-flaw catch rate** | **100%** (3/3) |
| **Gate block rate on vulnerable seeds** | **100%** (3/3) |
| **Remediation cleanliness** | **100%** (3/3) |
| **Average latency** | **24.2 s** |
| **Median latency** | **12.6 s** |

**Definitions.**

- *First-pass* — the gate returned `PASS` on the coder's very first attempt and
  the held-out suite also passed.
- *Self-corrected* — attempt 1 failed, the loop retried, and a later attempt
  reached `PASS` with the held-out suite passing.
- *Final pass* — first-pass plus self-corrected.
- *Security-flaw catch* — the deterministic scanner reports a security finding
  on the **seeded vulnerable source** for each security task.
- *Gate block* — the real scanner + real pytest + real routing function refuse
  to `PASS` that seeded source.
- *Remediation cleanliness* — the code that finally passed carries no security
  finding.

---

## Per-task breakdown

| Task | Category | Verdict | Attempts | Held-out suite | Latency |
| --- | --- | --- | --- | --- | --- |
| `b01_slugify` | coding | PASS | 1 | PASS | 12.93 s |
| `b02_parse_duration` | coding | ESCALATE_TO_HUMAN | 3 | FAIL | 93.53 s |
| `b03_chunk_list` | coding | PASS | 1 | PASS | 9.33 s |
| `b04_buggy_off_by_one` | bugfix | PASS | 1 | PASS | 8.21 s |
| `b05_buggy_mutable_default` | bugfix | PASS | 1 | PASS | 11.82 s |
| `b06_buggy_silent_except` | bugfix | PASS | 1 | PASS | 18.09 s |
| `b07_secure_password_store` | security | PASS | 1 | PASS | 12.06 s |
| `b08_secure_sql_lookup` | security | PASS | 1 | PASS | 12.26 s |
| `b09_secure_eval_trap` | security | PASS | 1 | PASS | 18.73 s |
| `b10_buggy_bare_typing` | bugfix | PASS | 3 | PASS | 45.01 s |

---

## What the two non-first-pass tasks actually show

### `b10_buggy_bare_typing` — a genuine self-correction (3 attempts)

`average()` is the deliberate "untyped, crashes on empty input, hides
type errors" seed. The acceptance suite exercises three behaviours: the mean is
correct, an empty list raises `ValueError`, and a non-numeric element raises
`TypeError`. Attempts 1 and 2 were rejected by real pytest failures; attempt 3
satisfied every criterion and the held-out suite. This is the loop doing the
job it exists for.

### `b02_parse_duration` — an honest escalation, not a silent pass

The gate tried three times and **escalated to a human** rather than declaring
success. On a re-run of the same task the pipeline passed on attempt 1, so this
is coder sampling variance on a genuinely tricky spec: `parse_duration` must
accept units in *any* order (`'30m1h'`), and a regex that assumes descending
order looks plausible and passes a naive test.

This is the most important row in the table. A weaker system would have
returned `PASS` on a parser that silently fails on out-of-order input, because
its tests only covered the easy shapes. Here the held-out suite caught it, the
gate refused to pass it, and the case ended in
`ESCALATE_TO_HUMAN` with the failing evidence written into the state.

I deliberately did **not** re-run until the number looked better. The lead
metric is reported as 80% first-pass / 90% final, and this run is the artifact.

---

## Security results in detail

All three seeded vulnerabilities were caught, blocked, and repaired.

| Task | Injected flaw | Detected rule | Gate | Final code |
| --- | --- | --- | --- | --- |
| `b07_secure_password_store` | `API_KEY = "sk-live-…"` literal | `HARDCODED_SECRET` (critical) | blocked | reads `os.environ`, raises `ValueError` when missing |
| `b08_secure_sql_lookup` | `f"SELECT … WHERE id = {user_id}"` | `SQL_STRING_FORMAT` (high) | blocked | parameterised `?` + params tuple |
| `b09_secure_eval_trap` | `return eval(text)` | `EVAL_EXEC` (critical) | blocked | `ast.literal_eval` with dict/int validation |

Each of these is verified deterministically by
`tests/test_benchmark_integrity.py`, which asserts that the seed is flagged,
that the gate refuses to pass it, and that the held-out suite rejects it — all
without spending an LLM token, so the security guarantee is enforced in CI on
every commit.

---

## Why the latency numbers look the way they do

Median 12.6 s, average 24.2 s — the average is dragged up by the two
three-attempt tasks (93.5 s and 45.0 s). Per task, roughly:

| Phase | Typical cost |
| --- | --- |
| Coder LLM call | 3–34 s (dominated by provider variance) |
| Static + security scan | < 20 ms |
| Sandboxed pytest (~1.3–2.5 s per run) | 1–3 s |
| Reviewer LLM call (only on failure) | 2–6 s |

The single cheapest thing to optimise is not the scanner — it is the coder's
response time. The slowest observed call (34 s for a 1.3 KB module) is the
provider, not this code.

---

## Reproducibility

```bash
git clone <repo> && cd codeguard-multiagent
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # set CODEGUARD_API_KEY

python -m pytest -q                 # 92 passed, 3 skipped, no API calls, ~43 s
python -m eval.run_benchmark        # the table above
```

The unit suite is fully offline: 92 tests, 0 tokens. `eval/results.json` is a
machine-readable copy of this run (gitignored, regenerated locally).

---

## Honest caveats

1. **Ten tasks is a smoke test, not a study.** It proves the loop and the gate
   work; it does not establish a general pass rate. 80% on ten hand-written
   tasks has a wide confidence interval.
2. **Results are model-specific.** A different backing model will move the
   first-pass rate, probably a lot. The timestamp and model are recorded in
   `results.json` so a stale number is never passed off as current.
3. **Two harness bugs were found and fixed during development**, and both are
   worth knowing about because they inflated earlier numbers:
   - The containment template defaulted to `min_args=1`, so a correct
     zero-argument function could never pass — it produced a fake
     "self-correction".
   - The security metric originally looked for the flaw in the *final* code,
     which reported 0% catch because the coder had already repaired the seed.
     It now measures the guard against the seed itself.
4. **One escalation is not a flake to be averaged away.** `b02` is reported as
   `ESCALATE_TO_HUMAN` because that is what the system returned.
