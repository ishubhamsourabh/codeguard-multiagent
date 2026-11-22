# Architecture Q&A — codeguard-multiagent

Notes for explaining this system in a technical interview: the decisions, the
trade-offs, and the questions that actually get asked.

---

## 1. Why multi-agent instead of one big prompt?

Because the three jobs have **different trust requirements**, and one prompt
can't hold all three simultaneously.

| Job | Trust model | Why separate |
| --- | --- | --- |
| Write code | Probabilistic, creative | Temperature 0.2; benefits from room to explore |
| Judge correctness | Deterministic, adversarial | `ast` + `pytest`; a model must never grade its own work |
| Explain the fix | Structured, reproducible | Temperature 0, JSON-schema-validated |

The decisive point is the middle row. If a single LLM both writes and grades the
code, you have a system whose quality metric is "does the model agree with
itself." Splitting the roles lets the gate be something a reviewer can audit:
exit codes from `pytest` and findings from a parser.

The reviewer is deliberately the **weakest** agent in terms of authority. It
cannot pass or fail anything. Its output is prose-shaped instructions for the
next attempt, and if its output is unusable the system falls back to a
deterministic verdict without losing correctness.

---

## 2. Why is the static scanner a deterministic AST pass rather than an LLM?

Three reasons, in order of importance:

1. **Reproducibility.** The same code must produce the same findings every run.
   A scanner whose verdict shifts with sampling temperature is not a gate.
2. **Cost and latency.** Scanning is microseconds and free; a model call is
   seconds and billed. The scanner runs on *every* attempt of *every* task.
3. **Adversarial robustness.** Code that is trying to sneak past review is
   exactly the input an LLM judge is weakest against. `ast` doesn't get
   persuaded by a comment that says "this is safe."

The AST pass is what understands scope: it knows the difference between a
string named `api_key` assigned a literal and a string *called* `api_key`
assembled at runtime. The regex pass catches what the AST treats as an
anonymous constant — a bearer token embedded in prose, an AWS key in a
docstring. Running both and deduplicating on `(rule, line)` gives coverage
neither has alone.

**Honest limitation:** this is pattern matching, not dataflow analysis. Taint
that crosses three functions won't be caught. It targets the classic,
high-signal flaws where a false negative is expensive and a false positive is
rare.

---

## 3. How do you prevent the loop from spinning forever?

Two independent mechanisms:

- **Explicit budget.** `iterations < max_iterations` is the only retry
  condition. When it's exhausted the graph routes to `escalate`, which is a
  terminal node.
- **Recursion limit.** LangGraph's own `recursion_limit` is set to
  `4 * (max_iterations + 2)`, so even a routing bug terminates with an error
  rather than hanging.

Both matter. The budget is the product behaviour (three attempts, then a human
decides); the recursion limit is the safety net for a bug in the routing
function itself.

---

## 4. Walk me through the state design. Why does `history` accumulate but `static_issues` doesn't?

This is the subtlest decision in the system, and getting it wrong produces a
bug that looks like a *correctness* bug but is really a *state* bug.

LangGraph channels either overwrite on each write or accumulate via a reducer.
My first version used a reducer for `static_issues`, which meant attempt 1's
findings were still in state at attempt 3. A coder that correctly fixed the
`eval()` call would still fail the gate, because the old finding was never
cleared. The loop would burn all three attempts on an issue that no longer
existed and escalate a correct answer.

So the split is:

- **Per-attempt artifacts** (`generated_code`, `static_issues`,
  `security_issues`, `test_results`) — plain channels that **overwrite**. They
  describe *this* candidate, not the whole session.
- **Session history** (`history`) — annotated with a concat reducer so the audit
  trail accumulates. This is what the escalation report and the benchmark read.

The general rule: a channel should accumulate only if the *history* is the
thing you need. If the value is a property of the current attempt, accumulating
it silently corrupts the gate.

---

## 5. How do you test a system that depends on an LLM?

By making the LLM the least testable part and testing everything around it.

- **Pure functions everywhere.** `build_coder_prompt`, `decide_route`,
  `scan_source`, `parse_review_json` are all deterministic and take plain data.
  The gate policy has ~12 unit tests that never touch a network.
- **Dependency injection.** Every agent factory accepts `client=`. Tests pass a
  `ScriptedCoder` or `FakeLLM` and assert the graph's routing, iteration count,
  and verdict — the actual loop logic, not the model.
- **Contract tests on the judge.** `ReviewVerdict` is a Pydantic model with
  `extra="forbid"`, so a judge that invents a key or a `"MAYBE"` verdict fails
  validation instead of silently passing through.
- **Fallback tests.** There is a test that the node survives an LLM raising
  `RuntimeError` and still produces a usable verdict.

The result: 92 offline tests run in ~43 s with zero API calls and zero cost, and
CI is green or red for reasons that have nothing to do with model mood.

---

## 6. What's the actual security model of the sandbox? Be precise.

It is **process isolation and filesystem hygiene**, not a security boundary.
Specifically:

- Fresh `tempfile.mkdtemp()` per run, deleted in a `finally`.
- `cwd` set to that directory so relative writes don't touch the repo.
- `PYTHONPATH` restricted to the sandbox so generated code can't import the
  project's own modules.
- Environment filtered to an allowlist (`PATH`, `SYSTEMROOT`, `TEMP`, …) so API
  keys in the parent env are not visible to candidate code.
- Hard wall-clock timeout, plus `pytest-timeout` as a second layer inside the
  process.

What it does **not** do: drop privileges, restrict syscalls, cap memory, or
block network egress. Code running here is the same OS user as the service.
For untrusted input the correct answer is a container with a read-only mount,
no network, and a memory cap — and I say so in the README rather than implying
the temp dir is a jail.

---

## 7. Your benchmark says 100% pass. Isn't that suspicious?

It should be, and that's why the harness is built the way it is.

- **The scoring suite is held out.** The coder never sees `hidden_tests`. A task
  counts as passed only when the gate says PASS **and** the held-out suite
  passes. The gate's own containment tests only check importability, entry-point
  existence, arity, and that a call doesn't crash — they are not the quality
  bar.
- **The security metric measures the guard, not the coder.** My first version
  measured catch rate by looking for the flaw in the *final* code. It reported
  0% — because the coder had already repaired the seeded bug on attempt 1, so
  there was nothing left to catch. That's a measurement bug that made a working
  guard look broken. The fix: evaluate the scanner against the **seeded
  vulnerable source** and separately ask the gate whether it would PASS that
  source. Both now report 100%, and both are deterministic.
- **10 tasks is a smoke test, not a study.** It's enough to show the loop works
  and the gate is not blind. It is not enough to claim a general pass rate, and
  the README says so.

The most valuable number in that table isn't the 100% — it's the **self-corrected
row**, because it's the only one that proves the retry loop does something.

---

## 8. A task failed attempt 1 and passed attempt 2. How do you know the retry was real?

You have to look, because a retry can be fake in two ways: the failure was
unrelated to the code, or the second attempt passed by luck.

When b07 (`build_headers`, a zero-argument function) failed attempt 1, the
reviewer's diagnosis was *"add at least one positional parameter so the
signature satisfies `assert len(positional) >= MIN_ARGS`."* That's a harness
bug talking: my containment template defaulted to `min_args=1`, so a correct
zero-arg function could never satisfy it. The "self-correction" was the coder
patching around my broken test.

The fix was to declare `min_args=0` for that task, plus a regression test
(`test_no_task_declares_a_false_arity`) that parses each seed's real signature
and asserts the declared arity doesn't exceed it. The lesson generalises: when
the loop reports a fix, read the reviewer's instructions — if they describe
something the *task* never asked for, the bug is in the harness.

---

## 9. Why typed whole-file regeneration instead of diffs or function patches?

Deliberate trade-off for this scale:

- **Whole file** — the model always returns a complete, coherent module. No
  patch application logic, no context-mismatch failures, no half-applied edits.
  Cost: tokens scale with file size, and an unrelated regression can slip in.
- **Diff/patch** — cheaper, but you now need fuzz-matching, and a failed hunk
  produces a corrupt file that's worse than the original.

At ~50–200 line modules, whole-file regeneration is both simpler and more
robust. The guard against regressions is that the gate re-runs on the whole
file every attempt — a regression is caught, not carried forward. If modules
grew to thousands of lines I'd switch to function-scoped edits with a diff
contract.

---

## 10. What breaks first at scale?

In order:

1. **Sandbox startup cost.** Each attempt spawns a Python process and imports
   pytest (~1.5–2.5 s here). At hundreds of concurrent validations this is the
   bottleneck. Fix: a warm worker pool with pre-imported pytest, or `pytest`
   in-process with `xdist` per isolated dir.
2. **LLM latency dominates wall clock.** Median 12 s per task, of which ~2–5 s
   is model time and the rest is the retry loop. Fix: cache the coder by
   `(intent_hash, attempt)`, and don't re-call the reviewer when the failure
   signature is identical to the previous attempt.
3. **Temp-dir churn.** Thousands of `mkdtemp` dirs in a `finally` is fine until
   a process is SIGKILLed mid-run and leaks them. Fix: a reaper on startup and a
   bounded, reused pool.
4. **The scanner's regex pass is O(rules × lines) per file.** Fine at 200 lines,
   noticeable at 20k. Fix: single combined alternation with named groups.

---

## 11. How would you make the verdict shippable as a real CI gate?

The current design already separates *evidence* from *judgement*, which is what
makes it gateable. Concretely I'd add:

- **A baseline file.** Commit known, accepted findings so the gate only fails on
  *new* ones — otherwise it blocks every PR the day it's introduced.
- **Diff-scoped scanning.** Validate the changed files, not the repo, so the
  signal-to-noise ratio stays usable.
- **A machine-readable exit path.** `ESCALATE_TO_HUMAN` should exit non-zero
  with a JSON body on stdout, so the CI step annotates the PR rather than
  requiring someone to read logs.
- **An audit record per run.** The `history` list already carries every attempt;
  persisting it gives reviewers "attempt 1 failed because X, attempt 2 fixed it"
  rather than just a red check.

---

## 12. What would you do differently if you rebuilt it?

- **Persist every attempt's code**, not just the latest. It would make the
  security metric measurable on real coder output instead of on the seed, and
  make the audit trail complete. This is the single change I'd make first.
- **Make `min_args` derive from the intent signature** instead of a hand-set
  field. Two arity bugs came from it being declared separately from reality.
- **Return typed errors from the runner** (`timeout` / `import_error` /
  `assertion` / `harness`) so the reviewer prompt can say *"this is an import
  error, not a logic error"* instead of describing raw pytest output.
- **Put the gate policy in its own module** rather than in `graph.py`. It's
  already a pure function; it deserves to be importable without pulling in
  LangGraph.
