# guardrail — Large-Context Benchmark

- Date: 2026-09-18 · Model: `jev-1.13.0` · Concurrency: 4
- Haystack: real Python sources concatenated to target size; needles injected
  at 5% / 50% / 95% offsets. Reproduce: `TYPESAFE_API_KEY=... python bench.py`

## API hard limit (verified)

| State size | input_tokens | Result |
|---|---|---|
| 55KB | ~28.3k | ✅ OK |
| 60KB | ~30.9k | ✅ OK |
| 65KB+ | ~33.5k+ | ❌ `400 max_tokens_exceeded` |

**Limit ≈ 32K input tokens (~62KB of Python source, ~0.51 tok/char).**
`main.py` previously allowed up to 200KB — states in the 62–200KB band were
guaranteed to 400 and (fail-closed) block the commit. **Fixed:** state is now
chunked at 50K chars with recursive halving on `max_tokens_exceeded`, and
results aggregate (max noul / worst quality / highest-confidence scope).

## Detection vs context size & position

| Case | Size | secret | vuln | Verdict |
|---|---|---|---|---|
| clean | 10KB | 0.02 | 0.05 | pass |
| secret@5% | 10KB | 0.91 | — | **BLOCK** |
| secret@50% | 10KB | 0.91 | — | **BLOCK** |
| secret@95% | 10KB | 0.84 | — | **BLOCK** |
| sqli@50% | 10KB | — | 0.63 | pass ⚠️ |
| clean | 49KB | 0.02 | 0.04 | pass |
| secret@5% | 49KB | 0.85 | — | **BLOCK** |
| secret@50% | 49KB | 0.85 | — | **BLOCK** |
| secret@95% | 49KB | 0.91 | — | **BLOCK** |
| sqli@50% | 49KB | — | 0.61 | pass ⚠️ |

End-to-end via CLI: 280KB dir with a real secret file → 3 chunks, 2004ms,
secret=0.93 → **BLOCKED** (previously: guaranteed API 400).

## Latency

| Metric | Value |
|---|---|
| Single call, ~5–26k tokens | 338–937ms |
| Median | ~712ms |
| 280KB dir (3 sequential chunks) | 2004ms |

Latency scales mildly with input size; chunk-boundary effects dominate over
payload bytes within the same chunk.

## Findings

1. **Secret detection is position- and size-robust** up to the token limit:
   0.84–0.93 regardless of needle depth in up to 49KB of noise.
2. **Vulnerability detection dilutes in large context** — the same 3-line SQLi
   scores 0.98 standalone but ~0.61 buried in 10–49KB of unrelated code, i.e.
   *under the 0.8 gate*. Asymmetric sensitivity vs secrets. Mitigation that
   already exists: `git diff` input is naturally focused (changed lines only);
   the dilution risk mostly affects `guardrail audit <dir>` on large dirs.
   Smaller `CHUNK_CHARS` would sharpen recall at higher per-commit cost.
3. **Token ratio ~0.51 tok/char** for Python source — `CHUNK_CHARS=50_000` keeps
   ~26k tokens, safely under 32k with headroom for denser text; the recursive
   halve covers outliers.
4. **Quality/scope signals degrade gracefully** on bulk filler (keyword-table
   lexer files read as `Critical_Core`/low quality) — expected; diffs behave
   better than monolithic dumps.

## Round 2 — E2E & edge cases (real repos, real `git commit`)

| Case | Result |
|---|---|
| 150KB staged diff via hook | 4 chunks, 2332ms → PASSED |
| 80KB diff + appended secret via hook | 2 chunks, secret=0.91 → **BLOCKED**, commit aborted |
| Binary-ish file in diff (no NUL → git emits raw bytes) | **BUG FIXED**: `UnicodeDecodeError` crash → now `errors="replace"` on `git diff` output |
| Deleted-file diff | PASSED (0.04/0.04) |
| Unicode/emoji/CJK diff | PASSED |
| 80KB dense base64 (high tok/char) | 50KB chunk exceeded 32k tok → **recursive halve fired** → 3 chunks, PASSED |
| `audit` nonexistent path | Clean error, exit 1 |
| `audit` empty file | "Nothing to audit", exit 0 |
| `audit` binary file directly | Audits garbage bytes, PASSED (wastes 1 API call — accepted wart) |
| `install-hook` with existing pre-commit | Appends marked block, preserves existing lines |
| `install-hook` outside repo | Clean error, exit 1 |
| `install-hook` twice | Idempotent (marker block replaced, not duplicated) |

Bug found & fixed this round: `subprocess.run(text=True)` crashed on non-UTF-8
diff output — any commit touching a Latin-1/UTF-16/NUL-free binary file would
die. `errors="replace"` applied to the git subprocess decode.

## Honest limits of this benchmark

- Haystack is concatenated library source — representative of `audit <dir>`,
  less so of a real `git diff` (which is smaller and change-focused by nature).
- One needle per state; multi-secret/multi-vuln interaction not measured.
- Numbers are single-run samples; noul values vary ±0.05–0.10 between runs.
