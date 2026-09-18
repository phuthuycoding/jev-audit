"""Benchmark guardrail/Jev on large states: detection vs size, latency scaling."""

import asyncio
import glob
import statistics
import time

from typesafe_sdk import AsyncTypeSafeClient, TypeSafeError

from main import BLOCK_THRESHOLD, QUESTIONS

CONCURRENCY = 4
SECRET = 'AWS_SECRET_ACCESS_KEY = "k9Xm2vLpT8yB3nF5jH6dS1aC4eG0iUoW7qRzN"\n'
SQLI = 'def f(u):\n    return db.execute("SELECT * FROM t WHERE x=" + u)\n'


def build_haystack(target_bytes: int) -> str:
    """Concatenate real site-packages sources until target size."""
    files = sorted(
        glob.glob(".venv/lib/python3.14/site-packages/**/*.py", recursive=True),
        key=lambda p: -len(open(p, "rb").read()),
    )
    buf = []
    total = 0
    for p in files:
        data = open(p, encoding="utf-8", errors="replace").read()
        buf.append(f"=== {p.split('site-packages/')[-1]} ===\n{data}\n")
        total += len(data)
        if total >= target_bytes:
            break
    return "".join(buf)[:target_bytes]


def inject(haystack: str, needle: str, pos: float) -> str:
    idx = int(len(haystack) * pos)
    return haystack[:idx] + needle + haystack[idx:]


async def probe(client, sem, name, state):
    async with sem:
        t = time.perf_counter()
        try:
            r = await client.system_one(state={"document": state}, questions=QUESTIONS)
            ms = (time.perf_counter() - t) * 1000
            secret = r.nouls["has_secret_leak"].noul
            vuln = r.nouls["has_vulnerability"].noul
            quality = r.scores["code_quality"].score + 1.0
            scope = r.choices["change_scope"].choice
            tok = r.usage.input_tokens
            blocked = secret > BLOCK_THRESHOLD or vuln > BLOCK_THRESHOLD
            return {"name": name, "kb": len(state) / 1024, "ms": ms,
                    "secret": secret, "vuln": vuln, "quality": quality,
                    "scope": scope, "tok": tok, "blocked": blocked, "err": ""}
        except TypeSafeError as e:
            return {"name": name, "kb": len(state) / 1024, "ms": (time.perf_counter() - t) * 1000,
                    "err": f"{type(e).__name__}: {e}"}


async def main():
    sizes = [10_000, 50_000, 100_000, 200_000]
    jobs = []
    for size in sizes:
        hay = build_haystack(size)
        jobs.append((f"clean_{size//1000}k", hay))
        jobs.append((f"secret@5%_{size//1000}k", inject(hay, SECRET, 0.05)))
        jobs.append((f"secret@50%_{size//1000}k", inject(hay, SECRET, 0.50)))
        jobs.append((f"secret@95%_{size//1000}k", inject(hay, SECRET, 0.95)))
        jobs.append((f"sqli@50%_{size//1000}k", inject(hay, SQLI, 0.50)))
    jobs.append(("oversize_500k", build_haystack(500_000)))

    sem = asyncio.Semaphore(CONCURRENCY)
    async with AsyncTypeSafeClient() as client:
        results = await asyncio.gather(*(probe(client, sem, n, s) for n, s in jobs))

    for r in results:
        if r["err"]:
            print(f"{r['name']:<18} {r['kb']:>6.0f}KB  ERR  {r['err'][:90]}")
        else:
            flag = "BLOCK" if r["blocked"] else "pass "
            print(f"{r['name']:<18} {r['kb']:>6.0f}KB  {r['ms']:>6.0f}ms  "
                  f"secret={r['secret']:.2f} vuln={r['vuln']:.2f} "
                  f"q={r['quality']:.1f} {r['scope']:<15} tok={r['tok']} {flag}")

    lat = [r["ms"] for r in results if not r["err"]]
    print(f"\nlatency: min={min(lat):.0f} med={statistics.median(lat):.0f} "
          f"max={max(lat):.0f}ms")


if __name__ == "__main__":
    asyncio.run(main())
