# Model Evaluation — Jev (`jev-1.13.0`) on the guardrail corpus

- Labeled cases: 73 | API errors: 0
- Gate threshold: noul > 0.8
- Labels: `is_secret`/`is_vuln` per-check ground truth (watch/ambiguous cases excluded — see `eval_model.py` LABELS)

## Confusion matrices @ 0.8

| Check | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| has_secret_leak | 20 | 0 | 0 | 53 | 1.00 | 1.00 | 1.00 |
| has_vulnerability | 22 | 1 | 0 | 50 | 0.96 | 1.00 | 0.98 |

## Threshold sweep (F1 / accuracy per gate)

| thr | secret P | secret R | secret F1 | vuln P | vuln R | vuln F1 |
|---|---|---|---|---|---|---|
| 0.50 | 0.95 | 1.00 | 0.98 | 0.63 | 1.00 | 0.77 |
| 0.55 | 1.00 | 1.00 | 1.00 | 0.69 | 1.00 | 0.81 |
| 0.60 | 1.00 | 1.00 | 1.00 | 0.79 | 1.00 | 0.88 |
| 0.65 | 1.00 | 1.00 | 1.00 | 0.85 | 1.00 | 0.92 |
| 0.70 | 1.00 | 1.00 | 1.00 | 0.92 | 1.00 | 0.96 |
| 0.75 | 1.00 | 1.00 | 1.00 | 0.96 | 1.00 | 0.98 |
| 0.80 | 1.00 | 1.00 | 1.00 | 0.96 | 1.00 | 0.98 |
| 0.85 | 1.00 | 0.90 | 0.95 | 1.00 | 0.95 | 0.98 |
| 0.90 | 1.00 | 0.70 | 0.82 | 1.00 | 0.91 | 0.95 |
| 0.95 | 1.00 | 0.25 | 0.40 | 1.00 | 0.68 | 0.81 |

### `secret` score separation

- positives (n=20): mean=0.92 min=0.83 median=0.93
- negatives (n=53): mean=0.04 max=0.52 median=0.03
- margin: lowest positive 0.83 vs highest negative 0.52

### `vuln` score separation

- positives (n=22): mean=0.95 min=0.84 median=0.97
- negatives (n=51): mean=0.32 max=0.82 median=0.27
- margin: lowest positive 0.84 vs highest negative 0.82

## Interpretation

- **`has_secret_leak` is cleanly separable** — positives floor at 0.83, negatives
  cap at 0.52. A wide, safe margin around the 0.8 gate.
- **`has_vulnerability` is a fuzzy boundary** — negative mean is 0.32 (vs 0.04 for
  secrets) and the top negatives sit at 0.77–0.82, a ~0.02 gap from the lowest
  positive (0.84). Credential-bearing URLs (`mongo_url` 0.79, `postgres_url`
  0.63), `chmod 777` (0.68) and `eval()`-laden code (`god_function` 0.77) all
  score "suspicious but not critical" — arguably calibrated, but they live right
  under the gate.
- **Run-to-run variance exists.** A borderline negative flipped to FP in one
  run (P=0.96) and stayed under in another (max 0.79) — noul values jitter
  ±0.05–0.10. Verdicts on cases near 0.8 are not perfectly stable; the 0.55–0.80
  plateau below suggests the *rate* of mistakes, not their identity, is what's
  stable.
- **Threshold choice validated:** vuln F1 peaks at 0.75–0.85, secret F1 is flat
  0.55–0.80 then collapses (recall 0.25 at 0.95). 0.8 sits at the joint optimum;
  lower thresholds buy nothing for secrets and invite borderline vuln FPs.
- **Caveat:** labels encode my judgment of "critical" — e.g. `verify=False` is
  labeled positive per tuned criteria while `md5`/`chmod 777` are labeled
  negative as hygiene issues. A different severity bar shifts the matrices.

## Latency

- min 232ms · median 277ms · max 1036ms (n=73)
