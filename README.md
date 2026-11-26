# codeguard-multiagent

A **multi-agent AI code validator and CI/CD quality gate**. A coder agent writes
Python from a structured intent prompt; a deterministic static/security scanner
and a sandboxed pytest runner judge the result; an LLM reviewer turns failures
into targeted fix instructions; a cyclic LangGraph loops until the code is clean
or the attempt budget is spent.

The design goal is that **no model gets to declare its own work correct**. Every
verdict is produced by running code and parsing ASTs, never by trusting prose.

**Live demo:** https://codeguard-multiagent.vercel.app — paste Python and get a
real 12-rule audit in the browser (no key, no login). The full coder → pytest →
reviewer loop needs a long-lived container; see [Deployment](#deployment).

| | |
| --- | --- |
| Tests | 110 passing, 3 skipped (offline, zero API calls) |
| Python | 3.11 – 3.13 |
| Lint | `ruff check` + `ruff format --check` clean |

```
                    ┌──────────────────────────────────────────────┐
                    │                                              │
  Intent ──▶ coder ─┴─▶ static_security ──▶ test_runner ──▶ gate ──┤
              ▲                                             │      │
              │                                    PASS ────┼──▶ END
              │                                             │
              └──────── reviewer ◀── fail & iterations < 3 ─┤
                                                            │
                            ESCALATE_TO_HUMAN ◀─────────────┘
                                        │
                                        ▼
                                       END
```

---

## Why the gate is trustworthy

| Concern | How it is handled |
| --- | --- |
| A model claims success falsely | Pass/fail comes from `pytest` exit codes and parsed counts |
| A model "fixes" a security bug by hiding it | Findings come from AST + regex analysis, not the model |
| A fix instruction is garbage | Reviewer JSON is Pydantic-validated; invalid output falls back to a deterministic verdict |
| Generated code hangs forever | pytest runs in a subprocess with a hard timeout |
| Generated code tampers with the repo | Tests run in a temp dir with a stripped environment and sandbox-only `PYTHONPATH` |
| A fixed bug keeps failing the gate | Findings are per-attempt; each iteration resets the issue lists |
| Infinite loops | `iterations < max_iterations` is the only retry condition, then escalation |

---

## Quick start

```bash
git clone <your-repo-url> codeguard-multiagent
cd codeguard-multiagent

python -m venv .venv
# Windows:  .venv\Scripts\activate
# POSIX:    source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # then set CODEGUARD_API_KEY
```

Validate something:

```bash
python -m pytest -q
uvicorn api:app --reload --port 8000
curl -s -X POST http://127.0.0.1:8000/validate-code \
  -H 'Content-Type: application/json' \
  -d '{
    "intent_spec": {
      "title": "Slug generator",
      "description": "Turn a title into a URL slug",
      "function_name": "slugify",
      "requirements": ["lowercase", "hyphen-separated", "strip edge hyphens"]
    }
  }'
```

Free, no-LLM scan of any Python file:

```bash
curl -s -X POST http://127.0.0.1:8000/scan \
  -H 'Content-Type: application/json' \
  -d "{\"code\": $(python -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' myfile.py)}"
```

---

## Architecture

| Path | Responsibility |
| --- | --- |
| `src/state.py` | `TypedDict` graph state: intent, code, issues, test results, verdict, iterations |
| `src/config.py` | Env-driven `Settings`; no network I/O at import time |
| `src/llm_client.py` | OpenAI-compatible client + code-fence extraction |
| `src/agents/coder_agent.py` | Generates (or repairs) Python from the intent spec |
| `src/agents/static_security_agent.py` | Deterministic `ast` + regex scanner — **no LLM** |
| `src/agents/test_runner_agent.py` | Sandboxed pytest execution with timeout |
| `src/agents/reviewer_agent.py` | Temperature-0 Pydantic JSON judge with deterministic fallback |
| `src/graph.py` | Cyclic LangGraph + the single pure routing function |
| `api.py` | FastAPI `/validate-code`, `/scan`, `/health` |
| `eval/` | 10-task benchmark and its harness |

### The scanner's rules

Blocking (`high`/`critical`) findings fail the gate; advisory ones are reported
but never block.

| Code | Severity | Detects |
| --- | --- | --- |
| `HARDCODED_SECRET` | critical | Credential-shaped literals: `sk-…`, `AKIA…`, `ghp_…`, `xox…`, `AIza…`, bearer tokens, PEM keys, and secret-named assignments |
| `EVAL_EXEC` | critical | `eval`, `exec`, `compile`, `__import__` |
| `EXEC_SHELL` / `SHELL_INJECTION` | high | `os.system`, `subprocess(..., shell=True)` with non-literal args |
| `UNSAFE_DESERIALIZE` | high | `pickle.load(s)` / `marshal` |
| `SQL_STRING_FORMAT` | high | SQL built via f-string, `%`, `.format()`, or concatenation |
| `SYNTAX_ERROR` | critical | Source that does not parse |
| `BARE_EXCEPT` | high | `except:` with no type |
| `BROAD_EXCEPT_PASS` | medium | `except Exception: pass` |
| `MUTABLE_DEFAULT_ARG` | medium | `def f(x=[])` |
| `MISSING_TYPE_HINT` | low | Unannotated public params or return |
| `MISSING_DOCSTRING` | low | Public function without a docstring |
| `WILDCARD_IMPORT` | low | `from module import *` |

Placeholder values (`"your-key-here"`, `"changeme"`, `<TOKEN>`, `${VAR}`) are
deliberately **not** flagged — the scanner avoids the classic false-positive
that makes secret scanners unusable.

---

## The loop

1. **coder** — writes a module from the intent. On retries it receives the
   previous code plus the reviewer's fix list, and must rewrite the module.
2. **static_security** — scans the code; splits findings into `static_issues`
   and `security_issues`.
3. **test_runner** — writes the module and a generated containment suite into a
   temp dir, runs `pytest` in a subprocess.
4. **gate** — a pure function: `PASS` when there are no blocking findings and
   tests pass; otherwise retry if budget remains, else escalate.
5. **reviewer** — temperature 0, JSON-only, schema-validated. Converts failures
   into ≤8 actionable instructions.

Retries are bounded by `CODEGUARD_MAX_ITERATIONS` (default 3). When the budget
is exhausted the graph ends with `ESCALATE_TO_HUMAN` and a written evidence
bundle: attempt count, blocking findings with line numbers, and test state.

---

## Results

Real numbers from an actual run — see [`RESULTS.md`](RESULTS.md) for the
environment, per-task breakdown, and honest caveats.

Reproduce:

```bash
python -m eval.run_benchmark                  # full 10 tasks
python -m eval.run_benchmark --limit 3        # quick smoke
python -m eval.run_benchmark --task b09_secure_eval_trap
```

The harness writes `eval/results.json` and prints first-pass %, self-corrected
pass %, security-flaw catch %, and mean/median latency.

### How the benchmark avoids flattering itself

- Every task has a **held-out pytest suite** the coder never sees; a task
  counts as passed only when that suite passes *and* the gate says `PASS`.
- Security catch rate is measured on the **seeded vulnerable source**, not on
  the coder's output. A coder that repairs the flaw on attempt 1 would
  otherwise make the guard look blind when it was never asked to judge.
- Gate block rate additionally runs the real scanner and real pytest against
  the vulnerable seed and asks the real routing function.
- Failures, escalations, and errors are reported, not filtered out.

---

## Deployment

The app serves its own front-end at `/`, so the deployed URL is directly usable.

### Vercel (demo — free, no API key needed)

Deployed at **https://codeguard-multiagent.vercel.app**.

```bash
npm i -g vercel
vercel deploy --prod
```

`vercel.json` is included. `.vercelignore` excludes `.env`, `.private/`, tests,
and the benchmark from the upload bundle — **without it Vercel uploads the whole
project directory, including any local `.env`.**

**`/validate-code` returns 501 on Vercel**, deliberately. A full validation takes
12–90 s (coder call + up to 3 retries + reviewer) and serverless functions are
capped at ~10–60 s. The endpoint refuses with an explanation instead of being
killed mid-run with an opaque timeout. `api.py` detects serverless via the
`VERCEL` env var.

### Container (full pipeline)

Any host that runs a long-lived process — Fly.io, Railway, Render, Cloud Run,
a VPS — supports the complete loop:

```bash
docker build -t codeguard .
docker run -p 8000:8000 -e CODEGUARD_API_KEY=... -e CODEGUARD_BASE_URL=... \
  -e CODEGUARD_MODEL=... codeguard
```

The image runs as a non-root user and has a `HEALTHCHECK` on `/health`.

**If you expose either deployment publicly**, put a request cap or auth in
front of it: every `/validate-code` call spends paid LLM tokens.

---

## CI/CD integration

`.github/workflows/ci.yml` runs three jobs:

1. **quality-gate** — `ruff` lint + format check, full unit suite on Python
   3.11 and 3.12, JUnit artifact upload.
2. **self-gate** — dogfooding: the deterministic scanner is run over `src/` and
   fails the build on any blocking finding.
3. **api-contract** — boots uvicorn, probes `/health`, and exercises `/scan`.

CI never calls the paid backend: the whole suite uses injected fakes, so it is
fast, deterministic, and free.

To gate a real PR, add a step that posts the diff to `/validate-code` and fails
on `ESCALATE_TO_HUMAN` or `FAIL`.

---

## Configuration

All via environment or `.env` (see `.env.example`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `CODEGUARD_API_KEY` | — | API key (falls back to `OPENAI_API_KEY`) |
| `CODEGUARD_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible endpoint |
| `CODEGUARD_MODEL` | `gpt-4o-mini` | Chat model |
| `CODEGUARD_MAX_ITERATIONS` | `3` | Coder attempts before escalation |
| `CODEGUARD_PYTEST_TIMEOUT` | `30` | Seconds per pytest run |
| `CODEGUARD_CODER_TEMPERATURE` | `0.2` | Coder sampling |
| `CODEGUARD_REVIEWER_TEMPERATURE` | `0.0` | Judge sampling — pinned |

---

## Limitations

- The scanner is pattern-based. It catches the classic, high-signal flaws; it is
  not a dataflow analyser and will miss taint that crosses several functions.
- The containment suite checks importability, entry-point existence, arity, and
  execution. Real behaviour is verified by the benchmark's held-out tests, not
  by the generated suite.
- Generated code runs as the same OS user. This is process isolation and
  filesystem hygiene, **not** a security boundary — use a container for
  untrusted input.
- Pass rates depend on the backing model. Numbers in `RESULTS.md` are from a
  specific model and date, not a guarantee.

## License

MIT.
