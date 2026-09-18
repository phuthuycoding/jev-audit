"""Run the test corpus through the real TypeSafe API and emit REPORT.md."""

import asyncio
import statistics
import sys
import time
from collections import defaultdict

from typesafe_sdk import AsyncTypeSafeClient, TypeSafeError

from main import BLOCK_THRESHOLD, QUALITY_THRESHOLD, QUESTIONS
from test_cases import CASES

CONCURRENCY = 6


async def run_case(client: AsyncTypeSafeClient, sem: asyncio.Semaphore, case: dict) -> dict:
    async with sem:
        started = time.perf_counter()
        try:
            r = await client.system_one(
                state={"document": case["code"], "source": case["name"]},
                questions=QUESTIONS,
            )
            ms = (time.perf_counter() - started) * 1000
        except TypeSafeError as e:
            return {**case, "error": str(e), "ms": (time.perf_counter() - started) * 1000}

    secret = r.nouls["has_secret_leak"].noul
    vuln = r.nouls["has_vulnerability"].noul
    quality = r.scores["code_quality"].score + 1.0
    scope = r.choices["change_scope"]
    blocked = secret > BLOCK_THRESHOLD or vuln > BLOCK_THRESHOLD
    verdict = "BLOCK" if blocked else ("WARN" if quality < QUALITY_THRESHOLD else "PASS")
    return {
        **case,
        "ms": ms,
        "secret": secret,
        "vuln": vuln,
        "quality": quality,
        "q_conf": r.scores["code_quality"].confidence,
        "scope": scope.choice,
        "s_conf": scope.confidence,
        "verdict": verdict,
        "ok": case["expect"] == "watch" or blocked == (case["expect"] == "block"),
    }


async def main() -> None:
    sem = asyncio.Semaphore(CONCURRENCY)
    async with AsyncTypeSafeClient() as client:
        results = await asyncio.gather(*(run_case(client, sem, c) for c in CASES))

    lat = [r["ms"] for r in results]
    errors = [r for r in results if "error" in r]
    judged = [r for r in results if "error" not in r]
    strict = [r for r in judged if r["expect"] != "watch"]
    misses = [r for r in strict if not r["ok"]]
    blocks = [r for r in judged if r.get("verdict") == "BLOCK"]

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_cat[r["cat"]].append(r)

    lines = [
        "# guardrail — Test Report",
        "",
        f"- Date: {time.strftime('%Y-%m-%d %H:%M')}",
        f"- Cases: {len(results)} | API errors: {len(errors)}",
        f"- Latency: min {min(lat):.0f}ms · median {statistics.median(lat):.0f}ms · "
        f"p95 {sorted(lat)[int(len(lat) * 0.95) - 1]:.0f}ms · max {max(lat):.0f}ms",
        f"- Accuracy (strict cases, n={len(strict)}): "
        f"{len(strict) - len(misses)}/{len(strict)} correct "
        f"({(len(strict) - len(misses)) / len(strict) * 100:.0f}%)",
        f"- Blocked: {len(blocks)} cases",
        "",
        "## Mismatches (expected vs actual)",
        "",
    ]
    if misses:
        for r in misses:
            lines.append(
                f"- **{r['name']}** ({r['cat']}): expected `{r['expect']}`, got "
                f"`{r['verdict']}` — secret={r['secret']:.2f} vuln={r['vuln']:.2f}"
            )
    else:
        lines.append("- None. All strict expectations matched.")
    lines += ["", "## Watch cases (borderline, no assertion)", ""]
    for r in judged:
        if r["expect"] == "watch":
            lines.append(
                f"- **{r['name']}** ({r['cat']}): `{r['verdict']}` — "
                f"secret={r['secret']:.2f} vuln={r['vuln']:.2f} quality={r['quality']:.1f}"
            )
    lines += ["", "## Full results", ""]
    lines.append("| Case | Category | Expect | Verdict | secret | vuln | quality | scope | ms |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in results:
        if "error" in r:
            lines.append(f"| {r['name']} | {r['cat']} | {r['expect']} | ERROR | — | — | — | — | {r['ms']:.0f} |")
        else:
            flag = "" if r["ok"] else " ⚠️"
            lines.append(
                f"| {r['name']} | {r['cat']} | {r['expect']} | {r['verdict']}{flag} | "
                f"{r['secret']:.2f} | {r['vuln']:.2f} | {r['quality']:.1f} | "
                f"{r['scope']} | {r['ms']:.0f} |"
            )
    with open("REPORT.md", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"done: {len(judged)}/{len(results)} judged, {len(misses)} mismatches")
    for r in misses:
        print(f"  MISS {r['name']}: expect={r['expect']} verdict={r['verdict']} "
              f"secret={r['secret']:.2f} vuln={r['vuln']:.2f}")
    for r in errors:
        print(f"  ERR  {r['name']}: {r['error']}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
