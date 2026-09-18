# guardrail — Test Report

- Date: 2026-09-18 12:49
- Cases: 79 | API errors: 0
- Latency: min 228ms · median 283ms · p95 655ms · max 874ms
- Accuracy (strict cases, n=64): 64/64 correct (100%)
- Blocked: 45 cases

## Methodology

- 79 hand-written cases across 9 categories: `secret`, `placeholder`, `injection`,
  `deser`, `web`, `config`, `safe`, `quality`, `diff` (git-diff semantics).
- Each case sent as `state={"document": ...}` to Jev (`jev-1.13.0`) with the exact
  `QUESTIONS` + thresholds from `main.py` — same code path as the CLI.
- `expect`: `block`/`allow` are hard assertions; `watch` = known gray zone, recorded only.
- All secrets in the corpus are fabricated. Runs: `run_tests.py` (regenerate with
  `TYPESAFE_API_KEY=... python run_tests.py`).

## Findings

1. **Criteria quality dominates accuracy.** Baseline instructions (naming only
   "SQLi / Command Injection / XSS") scored **90%** (57/63) — deserialization,
   SSRF, JWT-verify-off landed at 0.16–0.69, under threshold. Enumerating vuln
   classes + describing the `true`/`false` outcomes lifted strict accuracy to
   **100%** with zero new false positives.
2. **Jev has implicit entropy judgment.** Synthetic secrets with visible patterns
   (sequential hex, repeated base64) scored 0.72–0.79 — just under the 0.8 gate.
   A real `openssl genrsa` PEM scored >0.8. Consequence: the model deliberately
   discounts "obviously fake" secrets — good for fixtures, but any borderline
   real secret also lands in this band.
3. **The 0.7–0.8 band is the model's uncertainty zone.** `env_file` (0.72→0.93
   after criteria fix), `rsa_private_key` (0.79 before corpus fix),
   `open_redirect` (exactly 0.80). Lowering `BLOCK_THRESHOLD` to ~0.7 would catch
   these but likely block legit borderline code — kept 0.8 and fixed instructions
   instead.
4. **Semantic boundaries observed:** a hardcoded JWT *token* is not treated as a
   "secret" (0.12–0.22, consistent across runs) — Jev reads the question as
   "keys/passwords", and a bearer token is neither. Meanwhile `PASSWORD=""` +
   `DEBUG_PASSWORD="password123"` DID block (0.83) — hardcoded weak passwords count.
5. **Diff semantics work correctly.** `+API_KEY=...` blocks; the same key on a
   `-` removal line passes (0.25 earlier run). Comment-only diffs pass.
6. **Verify-bypass is treated as critical** (per tuned criteria):
   `verify=False` 0.97, `CERT_NONE` 0.95 — both block.
7. **Hygiene issues pass by design.** `md5`, `DES`, `random` tokens,
   `debug=True`, `mktemp`, `chmod 777` (0.71 close call), CORS `*` — all allowed.
   The question asks for *critical* vulns; if these should block, the criteria or
   a dedicated Noul is the lever, not the threshold.
8. **Latency reality:** median ~283ms, p95 ~655ms — fast, but the "<200ms" spec
   target is optimistic for real payloads.

## Recommendations

- Keep `BLOCK_THRESHOLD = 0.8`; invest in criteria wording instead (demonstrated
  +10pp accuracy).
- If JWT/session tokens must block, add a dedicated Noul ("hardcoded credential
  or token") — folding it into `has_secret_leak` confuses the key/password framing.
- Consider a separate low-severity Noul for hygiene issues if the team wants
  warnings for `verify=False`-adjacent patterns rather than silence.

## Mismatches (expected vs actual)

- None. All strict expectations matched.

## Watch cases (borderline, no assertion)

- **jwt_literal** (secret): `WARN` — secret=0.22 vuln=0.15 quality=2.4
- **doc_example_keys** (placeholder): `WARN` — secret=0.20 vuln=0.38 quality=1.9
- **empty_password** (placeholder): `BLOCK` — secret=0.83 vuln=0.37 quality=1.8
- **nosql_injection** (injection): `BLOCK` — secret=0.03 vuln=0.96 quality=1.5
- **xss_mark_safe** (web): `BLOCK` — secret=0.02 vuln=0.94 quality=1.9
- **open_redirect** (web): `WARN` — secret=0.02 vuln=0.80 quality=1.9
- **cors_wildcard_creds** (web): `WARN` — secret=0.02 vuln=0.56 quality=2.8
- **tls_verify_false** (config): `BLOCK` — secret=0.03 vuln=0.97 quality=2.1
- **ssl_no_hostname** (config): `BLOCK` — secret=0.02 vuln=0.95 quality=2.3
- **md5_password** (config): `WARN` — secret=0.09 vuln=0.19 quality=2.5
- **des_cipher** (config): `WARN` — secret=0.09 vuln=0.39 quality=2.2
- **random_token** (config): `WARN` — secret=0.03 vuln=0.27 quality=2.5
- **flask_debug** (config): `WARN` — secret=0.02 vuln=0.28 quality=2.5
- **chmod_777** (config): `WARN` — secret=0.03 vuln=0.71 quality=2.1
- **mktemp** (config): `WARN` — secret=0.02 vuln=0.20 quality=2.6

## Full results

| Case | Category | Expect | Verdict | secret | vuln | quality | scope | ms |
|---|---|---|---|---|---|---|---|---|
| aws_keypair | secret | block | BLOCK | 0.94 | 0.49 | 1.9 | Critical_Core | 824 |
| github_pat | secret | block | BLOCK | 0.90 | 0.48 | 1.9 | Critical_Core | 716 |
| github_fine_grained | secret | block | BLOCK | 0.87 | 0.35 | 2.0 | Critical_Core | 655 |
| rsa_private_key | secret | block | BLOCK | 0.92 | 0.57 | 1.9 | Critical_Core | 723 |
| openssh_key | secret | block | BLOCK | 0.85 | 0.33 | 2.0 | Critical_Core | 613 |
| jwt_literal | secret | watch | WARN | 0.22 | 0.15 | 2.4 | Critical_Core | 874 |
| slack_token | secret | block | BLOCK | 0.92 | 0.44 | 2.1 | Critical_Core | 277 |
| stripe_live | secret | block | BLOCK | 0.93 | 0.42 | 1.9 | Critical_Core | 260 |
| google_api_key | secret | block | BLOCK | 0.89 | 0.38 | 2.0 | Critical_Core | 325 |
| db_password_var | secret | block | BLOCK | 0.96 | 0.42 | 2.3 | Critical_Core | 344 |
| postgres_url | secret | block | BLOCK | 0.97 | 0.62 | 2.3 | Critical_Core | 286 |
| mongo_url | secret | block | BLOCK | 0.96 | 0.81 | 1.9 | Critical_Core | 259 |
| redis_url | secret | block | BLOCK | 0.93 | 0.57 | 2.5 | Critical_Core | 259 |
| basic_auth_url | secret | block | BLOCK | 0.94 | 0.67 | 1.6 | Critical_Core | 308 |
| env_file | secret | block | BLOCK | 0.95 | 0.36 | 2.5 | Critical_Core | 303 |
| bearer_header | secret | block | BLOCK | 0.82 | 0.34 | 2.6 | Critical_Core | 280 |
| paramiko_password | secret | block | BLOCK | 0.97 | 0.63 | 1.7 | Critical_Core | 295 |
| aws_session_token | secret | block | BLOCK | 0.92 | 0.55 | 2.0 | Critical_Core | 255 |
| npmrc_token | secret | block | BLOCK | 0.92 | 0.44 | 2.4 | Critical_Core | 251 |
| twilio_key | secret | block | BLOCK | 0.82 | 0.42 | 2.5 | Critical_Core | 357 |
| placeholder_caps | placeholder | allow | WARN | 0.04 | 0.15 | 1.5 | Minor_Fix | 281 |
| env_read | placeholder | allow | WARN | 0.04 | 0.17 | 2.5 | Critical_Core | 265 |
| dotenv_load | placeholder | allow | WARN | 0.04 | 0.07 | 2.8 | Critical_Core | 283 |
| secrets_manager | placeholder | allow | WARN | 0.06 | 0.16 | 2.3 | Critical_Core | 288 |
| test_fixture_dummy | placeholder | allow | PASS | 0.15 | 0.18 | 3.7 | Minor_Fix | 311 |
| example_config | placeholder | allow | PASS | 0.08 | 0.09 | 3.3 | Minor_Fix | 387 |
| redacted | placeholder | allow | WARN | 0.53 | 0.20 | 2.3 | Critical_Core | 284 |
| doc_example_keys | placeholder | watch | WARN | 0.20 | 0.38 | 1.9 | Critical_Core | 269 |
| comment_mentions_key | placeholder | allow | WARN | 0.05 | 0.16 | 2.2 | Minor_Fix | 283 |
| empty_password | placeholder | watch | BLOCK | 0.83 | 0.37 | 1.8 | Critical_Core | 278 |
| sqli_concat | injection | block | BLOCK | 0.02 | 0.98 | 1.8 | Critical_Core | 280 |
| sqli_fstring | injection | block | BLOCK | 0.02 | 0.98 | 1.7 | Critical_Core | 496 |
| sqli_format | injection | block | BLOCK | 0.02 | 0.97 | 1.8 | Critical_Core | 238 |
| sqli_percent | injection | block | BLOCK | 0.03 | 0.96 | 1.8 | Critical_Core | 261 |
| cmdi_os_system | injection | block | BLOCK | 0.02 | 0.97 | 1.7 | Critical_Core | 279 |
| cmdi_shell_true | injection | block | BLOCK | 0.02 | 0.96 | 1.7 | Critical_Core | 240 |
| cmdi_os_popen | injection | block | BLOCK | 0.02 | 0.98 | 1.8 | Critical_Core | 293 |
| eval_input | injection | block | BLOCK | 0.03 | 0.94 | 1.8 | Critical_Core | 274 |
| exec_input | injection | block | BLOCK | 0.05 | 0.92 | 1.4 | Critical_Core | 280 |
| ssti_jinja | injection | block | BLOCK | 0.02 | 0.86 | 1.9 | Critical_Core | 320 |
| ldap_injection | injection | block | BLOCK | 0.02 | 0.87 | 2.0 | Critical_Core | 302 |
| nosql_injection | injection | watch | BLOCK | 0.03 | 0.96 | 1.5 | Critical_Core | 242 |
| pickle_loads | deser | block | BLOCK | 0.02 | 0.98 | 1.8 | Critical_Core | 281 |
| yaml_load | deser | block | BLOCK | 0.05 | 0.94 | 2.2 | Critical_Core | 323 |
| marshal_loads | deser | block | BLOCK | 0.02 | 0.91 | 2.0 | Critical_Core | 256 |
| xss_innerhtml | web | block | BLOCK | 0.02 | 0.96 | 1.6 | Critical_Core | 269 |
| xss_mark_safe | web | watch | BLOCK | 0.02 | 0.94 | 1.9 | Critical_Core | 286 |
| path_traversal | web | block | BLOCK | 0.02 | 0.98 | 1.8 | Critical_Core | 276 |
| ssrf | web | block | BLOCK | 0.03 | 0.96 | 1.7 | Critical_Core | 270 |
| open_redirect | web | watch | WARN | 0.02 | 0.80 | 1.9 | Critical_Core | 289 |
| xxe_parse | web | block | BLOCK | 0.02 | 0.97 | 2.0 | Critical_Core | 285 |
| cors_wildcard_creds | web | watch | WARN | 0.02 | 0.56 | 2.8 | Critical_Core | 304 |
| tls_verify_false | config | watch | BLOCK | 0.03 | 0.97 | 2.1 | Critical_Core | 335 |
| ssl_no_hostname | config | watch | BLOCK | 0.02 | 0.95 | 2.3 | Critical_Core | 351 |
| jwt_no_verify | config | block | BLOCK | 0.03 | 0.98 | 2.0 | Critical_Core | 245 |
| md5_password | config | watch | WARN | 0.09 | 0.19 | 2.5 | Critical_Core | 279 |
| des_cipher | config | watch | WARN | 0.09 | 0.39 | 2.2 | Critical_Core | 262 |
| random_token | config | watch | WARN | 0.03 | 0.27 | 2.5 | Critical_Core | 340 |
| flask_debug | config | watch | WARN | 0.02 | 0.28 | 2.5 | Critical_Core | 313 |
| chmod_777 | config | watch | WARN | 0.03 | 0.71 | 2.1 | Critical_Core | 292 |
| mktemp | config | watch | WARN | 0.02 | 0.20 | 2.6 | Minor_Fix | 283 |
| empty_except | config | allow | WARN | 0.02 | 0.10 | 2.0 | Refactor | 268 |
| safe_param_sql | safe | allow | PASS | 0.02 | 0.03 | 4.1 | Critical_Core | 264 |
| safe_orm | safe | allow | WARN | 0.02 | 0.09 | 2.9 | Critical_Core | 228 |
| safe_subprocess | safe | allow | WARN | 0.02 | 0.55 | 2.7 | Refactor | 303 |
| safe_html_escape | safe | allow | PASS | 0.02 | 0.09 | 3.1 | Critical_Core | 381 |
| safe_bcrypt | safe | allow | WARN | 0.04 | 0.06 | 3.0 | Critical_Core | 394 |
| safe_secrets_mod | safe | allow | PASS | 0.07 | 0.04 | 4.1 | Critical_Core | 307 |
| safe_yaml | safe | allow | WARN | 0.04 | 0.11 | 2.5 | Minor_Fix | 398 |
| safe_path_check | safe | allow | PASS | 0.02 | 0.15 | 3.4 | Critical_Core | 297 |
| safe_jwt_verify | safe | allow | WARN | 0.04 | 0.15 | 2.4 | Critical_Core | 265 |
| safe_clean_fn | safe | allow | PASS | 0.02 | 0.04 | 3.6 | Refactor | 303 |
| god_function | quality | allow | WARN | 0.02 | 0.76 | 1.7 | Critical_Core | 278 |
| dead_code | quality | allow | WARN | 0.02 | 0.03 | 2.5 | Refactor | 270 |
| breaking_api | quality | allow | PASS | 0.03 | 0.15 | 3.3 | Breaking_Change | 267 |
| diff_adds_secret | diff | block | BLOCK | 0.94 | 0.65 | 1.6 | Critical_Core | 232 |
| diff_removes_secret | diff | allow | PASS | 0.11 | 0.25 | 3.1 | Critical_Core | 245 |
| diff_adds_sqli | diff | block | BLOCK | 0.03 | 0.99 | 1.4 | Critical_Core | 260 |
| diff_comment_only | diff | allow | PASS | 0.04 | 0.04 | 3.2 | Minor_Fix | 346 |
