"""Model evaluation: confusion matrix, precision/recall/F1, threshold sweep.

Labels are per-check ground truth: is_secret = has_secret_leak should fire,
is_vuln = has_vulnerability should fire. Only unambiguous cases are scored.
"""

import asyncio
import statistics
import time

from typesafe_sdk import AsyncTypeSafeClient, TypeSafeError

from main import BLOCK_THRESHOLD, QUESTIONS
from test_cases import CASES

CONCURRENCY = 6

# name -> (is_secret, is_vuln). Cases not listed are excluded from strict metrics.
LABELS = {
    # secrets → (True, False)
    **{n: (True, False) for n in [
        "aws_keypair", "github_pat", "github_fine_grained", "rsa_private_key",
        "openssh_key", "slack_token", "stripe_live", "google_api_key",
        "db_password_var", "postgres_url", "mongo_url", "redis_url",
        "basic_auth_url", "env_file", "bearer_header", "paramiko_password",
        "aws_session_token", "npmrc_token", "twilio_key",
    ]},
    # vulns → (False, True)
    **{n: (False, True) for n in [
        "sqli_concat", "sqli_fstring", "sqli_format", "sqli_percent",
        "cmdi_os_system", "cmdi_shell_true", "cmdi_os_popen",
        "eval_input", "exec_input", "ssti_jinja", "ldap_injection",
        "pickle_loads", "yaml_load", "marshal_loads",
        "xss_innerhtml", "path_traversal", "ssrf", "xxe_parse",
        "jwt_no_verify", "tls_verify_false", "ssl_no_hostname",
    ]},
    # negatives → (False, False)
    **{n: (False, False) for n in [
        "placeholder_caps", "env_read", "dotenv_load", "secrets_manager",
        "test_fixture_dummy", "example_config", "redacted",
        "comment_mentions_key", "empty_except",
        "md5_password", "des_cipher", "random_token", "flask_debug",
        "chmod_777", "mktemp", "cors_wildcard_creds",
        "safe_param_sql", "safe_orm", "safe_subprocess", "safe_html_escape",
        "safe_bcrypt", "safe_secrets_mod", "safe_yaml", "safe_path_check",
        "safe_jwt_verify", "safe_clean_fn",
        "god_function", "dead_code", "breaking_api",
        "diff_removes_secret", "diff_comment_only",
    ]},
    # diffs with labels
    "diff_adds_secret": (True, False),
    "diff_adds_sqli": (False, True),
}


async def probe(client, sem, case):
    async with sem:
        t = time.perf_counter()
        try:
            r = await client.system_one(
                state={"document": case["code"], "source": case["name"]},
                questions=QUESTIONS,
            )
            return {
                "name": case["name"],
                "secret": r.nouls["has_secret_leak"].noul,
                "vuln": r.nouls["has_vulnerability"].noul,
                "ms": (time.perf_counter() - t) * 1000,
            }
        except TypeSafeError as e:
            return {"name": case["name"], "err": str(e)}


def cm(rows, key, label_idx, thr):
    tp = fp = fn = tn = 0
    for r in rows:
        truth = LABELS[r["name"]][label_idx]
        pred = r[key] > thr
        tp += pred and truth
        fp += pred and not truth
        fn += (not pred) and truth
        tn += (not pred) and not truth
    return tp, fp, fn, tn


def f1(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


async def main():
    sem = asyncio.Semaphore(CONCURRENCY)
    async with AsyncTypeSafeClient() as client:
        results = await asyncio.gather(
            *(probe(client, sem, c) for c in CASES if c["name"] in LABELS)
        )
    rows = [r for r in results if "err" not in r]
    errors = [r for r in results if "err" in r]

    out = [
        "# Model Evaluation — Jev (`jev-1.13.0`) on the guardrail corpus",
        "",
        f"- Labeled cases: {len(rows)} | API errors: {len(errors)}",
        f"- Gate threshold: noul > {BLOCK_THRESHOLD}",
        "- Labels: `is_secret`/`is_vuln` per-check ground truth (watch/ambiguous"
        " cases excluded — see `eval_model.py` LABELS)",
        "",
        "## Confusion matrices @ 0.8",
        "",
        "| Check | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for key, idx, label in [("secret", 0, "has_secret_leak"), ("vuln", 1, "has_vulnerability")]:
        tp, fp, fn, tn = cm(rows, key, idx, BLOCK_THRESHOLD)
        p, r, f = f1(tp, fp, fn)
        out.append(f"| {label} | {tp} | {fp} | {fn} | {tn} | {p:.2f} | {r:.2f} | {f:.2f} |")

    out += ["", "## Threshold sweep (F1 / accuracy per gate)", ""]
    out.append("| thr | secret P | secret R | secret F1 | vuln P | vuln R | vuln F1 |")
    out.append("|---|---|---|---|---|---|---|")
    for thr in [x / 100 for x in range(50, 96, 5)]:
        line = f"| {thr:.2f} "
        for key, idx in [("secret", 0), ("vuln", 1)]:
            tp, fp, fn, tn = cm(rows, key, idx, thr)
            p, r, f = f1(tp, fp, fn)
            line += f"| {p:.2f} | {r:.2f} | {f:.2f} "
        out.append(line + "|")

    # score separation
    for key, idx, label in [("secret", 0, "secret"), ("vuln", 1, "vuln")]:
        pos = [r[key] for r in rows if LABELS[r["name"]][idx]]
        neg = [r[key] for r in rows if not LABELS[r["name"]][idx]]
        out += [
            "",
            f"### `{label}` score separation",
            "",
            f"- positives (n={len(pos)}): mean={statistics.mean(pos):.2f} "
            f"min={min(pos):.2f} median={statistics.median(pos):.2f}",
            f"- negatives (n={len(neg)}): mean={statistics.mean(neg):.2f} "
            f"max={max(neg):.2f} median={statistics.median(neg):.2f}",
            f"- margin: lowest positive {min(pos):.2f} vs highest negative {max(neg):.2f}",
        ]

    lat = [r["ms"] for r in rows]
    out += [
        "",
        "## Latency",
        "",
        f"- min {min(lat):.0f}ms · median {statistics.median(lat):.0f}ms · "
        f"max {max(lat):.0f}ms (n={len(lat)})",
    ]
    for r in errors:
        out.append(f"- ERROR {r['name']}: {r['err']}")

    open("EVAL.md", "w").write("\n".join(out) + "\n")
    print(f"wrote EVAL.md — {len(rows)} labeled cases, {len(errors)} errors")


if __name__ == "__main__":
    asyncio.run(main())
