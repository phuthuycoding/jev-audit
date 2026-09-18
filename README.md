# guardrail

**AI-powered pre-commit auditor backed by TypeSafe System One (Jev).**
Sends your code changes to Jev as a `State` and evaluates 4 atomic questions in a
single API call — no text generation, no parsing — typically ~300ms.

| Question | Primitive | Purpose |
|---|---|---|
| `has_secret_leak` | Noul | Detect hardcoded API keys, tokens, private keys, passwords |
| `has_vulnerability` | Noul | Detect SQLi, command injection, XSS, deserialization, SSRF, … |
| `code_quality` | Score | Rate code quality on a 1–5 scale |
| `change_scope` | Choice | Classify as `Minor_Fix` / `Refactor` / `Breaking_Change` / `Critical_Core` |

## Demo

```text
╭──────────────────────────────────────────────────────────────────────╮
│ 🛡  GUARDRAIL — AI Commit Audit                                       │
│ ⚡ Evaluated in 706ms (model: jev-1.13.0)                             │
╰──────────────────────────────────────────────────────────────────────╯
       guardrail audit — git diff HEAD (staged + unstaged)
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┓
┃ Check             ┃ Result / Score ┃ Confidence ┃ Status ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━┩
│ has_secret_leak   │ 0.97           │          — │ BLOCK  │
│ has_vulnerability │ 0.18           │          — │   OK   │
│ code_quality      │ 1.7 / 5        │       0.45 │  WARN  │
│ change_scope      │ Critical_Core  │       0.94 │  INFO  │
└───────────────────┴────────────────┴────────────┴────────┘
╭────────── ❌ COMMIT BLOCKED: Critical Security Threat Detected! ─────╮
│ • secret leak detected (noul=0.97)                                   │
│                                                                      │
│ Fix the issues above, or bypass with `git commit --no-verify`.       │
╰──────────────────────────────────────────────────────────────────────╯
```

## Test results (real API, `jev-1.13.0`)

- **79-case corpus → 100% strict accuracy** (`EVAL.md`: secret F1 = 1.00,
  vuln F1 = 0.98 @ threshold 0.8) across secrets, injection,
  deserialization, web vulns, placeholders, safe code, and git-diff semantics
  (see [REPORT.md](REPORT.md)). Jev understands diff context — a commit that
  *removes* a hardcoded secret passes; the same key on a `+` line blocks.
- **~32K input-token API limit discovered by bisect** — handled via 50KB chunking
  + recursive halving on `max_tokens_exceeded`.
- Secrets are position- and size-robust (0.84–0.93 buried in 49KB of noise);
  vulnerability scores dilute in large contexts — `git diff` input keeps them sharp.
- Jev applies implicit entropy judgment: patterned fake secrets score lower than
  real `openssl genrsa` keys. Placeholders (`changeme`, `YOUR_KEY_HERE`, canonical
  doc examples) correctly pass.
- Bug found by E2E testing: `UnicodeDecodeError` crash on non-UTF-8 diff bytes —
  fixed with `errors="replace"`.

## Install

```sh
pip install .          # or: pipx install .
export TYPESAFE_API_KEY=ts-...   # https://console.typesafe.ai/
```

## Usage

```sh
guardrail audit              # audit `git diff HEAD` (staged + unstaged vs last commit)
guardrail audit src/app.py   # audit a file
guardrail audit src/         # audit every text file under a directory
guardrail install-hook       # wire `guardrail audit` into .git/hooks/pre-commit
```

## Try it on the bundled examples

```sh
guardrail audit examples/leaky.py        # fake secrets    → ❌ BLOCKED
guardrail audit examples/vulnerable.py   # SQLi/CMDi/XSS   → ❌ BLOCKED
guardrail audit examples/messy.py        # poor quality    → ⚠️ WARN + PASSED
guardrail audit examples/clean.py        # clean code      → ✅ PASSED
```

All secrets in `examples/` and `test_cases.py` are fabricated for testing.

## Verdicts

- `has_secret_leak > 0.8` or `has_vulnerability > 0.8` → **❌ COMMIT BLOCKED**, exit 1
- `code_quality < 3.0` → **⚠️ WARNING** (commit still allowed)
- otherwise → **✅ PASSED**, exit 0

The tool is **fail-closed**: missing `TYPESAFE_API_KEY`, network errors, or API
errors block the commit rather than letting unaudited code through. To bypass in
an emergency:

```sh
git commit --no-verify
```

## Repo layout

```
main.py         # CLI: audit + install-hook, rule engine, chunking, rich UI
test_cases.py   # 79-case corpus (all secrets fabricated)
run_tests.py    # corpus runner → REPORT.md
bench.py        # large-context benchmark → BENCHMARK.md
REPORT.md       # full test matrix + findings
BENCHMARK.md    # size/latency/token-limit results
EVAL.md         # model eval: confusion matrix, P/R/F1, threshold sweep
eval_model.py   # eval runner → EVAL.md
```

## Notes

- `typesafe-sdk` is the official package (`typesafe-ai` on PyPI is a defensive
  shim that just re-exports it).
- Jev's `Score` primitive is 0-indexed; guardrail maps it `+1` so the rubric
  displays as the requested 1–5 scale.
- Directory audits skip binary files, files >512KB, common noise directories
  (`node_modules`, `.venv`, …) and truncate the state at ~200k chars, split into
  ~50KB chunks to stay under the API token limit.
