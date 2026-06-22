# σ-gate — deterministic trust layer for AI/agent output

> **1 = 1.** Declared output must match what's safe to realize. The σ-gate enforces that boundary
> *deterministically* — same input, same verdict, every time. No model, no API key, no network.

This repository is the **open core** of the Spektre σ-gate. It ships [`guard`](guard/) — a
zero-dependency, standard-library Python trust gate that turns one call into a single ship/block verdict:

```python
from guard import guard

guard("Here is the key: ghp_16C7e42F292c6912E7710c838347Ae178B4a")
# {"safe_to_ship": False, "severity": "high",
#  "block_reasons": ["secret[high]: github_pat"], "dimensions": {...}}
```

## Two layers

| Layer | What it does | Where |
|---|---|---|
| **`guard` (open core, here)** | Deterministic pre-ship gate: leaked secrets (20+ providers, entropy), prompt-injection / jailbreak, PII (email/phone/card-Luhn/SSN/IBAN/IP) → one verdict | this repo, free |
| **Hosted σ scoring** | Coherence / hallucination scoring on a hot path (~85µs), pay-per-call | [swagletz-sigmagate.hf.space](https://swagletz-sigmagate.hf.space) |

The point of an LLM-as-judge guard is reproducibility — yet model judges are slow, cost a call per
check, and silently degrade when an upstream rate-limits. For the classes of risk that are
*structurally detectable* — an `AKIA…` key, a `4111…` card number, an "ignore all previous
instructions" — you don't need a model. You need a gate that gives the **same answer every time**.
`guard` is that gate.

## Use it

```bash
python3 -m pytest -q          # 7 passing tests, zero dependencies
```

```python
from guard import guard
v = guard(model_output)
if not v["safe_to_ship"]:
    raise ValueError(v["block_reasons"])
```

## Hosted (optional)

For coherence/hallucination σ-scoring without running anything yourself:

```bash
curl "https://swagletz-sigmagate.hf.space/check?text=your+text+here"
# HTTP 402 + a permissionless pay-to (x402) — no signup
```

## Design

- **Deterministic.** No model, no network, no key. Same input → same verdict.
- **Composable.** Each dimension (`secret`, `injection`, `pii`) is independent and pluggable; a
  hallucination scorer can be wired in but is off by default.
- **Honest.** Severity and block-reasons are explicit; nothing is hidden behind a confidence float.

Part of [Spektre Labs](https://github.com/spektre-labs) — a coherence-theory research lab.
`1 = 1`, made executable. License: see [LICENSE](LICENSE).
