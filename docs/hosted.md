# σ-gate hosted endpoint

**Base URL:** `https://swagletz-sigmagate.hf.space`

---

## When to use hosted vs open-core

| | Open-core (`guard`) | Hosted (`/check`) |
|---|---|---|
| **What** | Structural detection: leaked secrets, prompt-injection, PII | Coherence / hallucination σ-scoring |
| **Latency** | ~85µs, in-process | Network round-trip |
| **Model** | None | Optional (probabilistic) |
| **Cost** | Free, zero-dependency | Pay-per-call via x402, no signup |
| **Offline** | Yes | No |
| **Install** | `git clone` + `from guard import guard` | `curl` or `requests` |

**Rule of thumb:** use the open-core for anything structurally detectable — a leaked `AKIA…` key, a card number, an injection payload. The structural gate gives the same verdict every time at zero cost. Use the hosted endpoint when you need probabilistic coherence scoring: does this output contradict the context? Is the model hedging or fabricating? That requires a hot path with optional model inference that doesn't belong in a zero-dependency local library.

---

## `/check` — coherence / hallucination σ-score

Returns a 0–1 σ-score measuring how well the output coheres with the supplied context. `sigma=1.0` means declared output matches realized meaning. `sigma<0.5` typically indicates hedging, contradiction, or hallucination.

### Request

```
GET /check?text=<url-encoded-text>&context=<url-encoded-context>
```

| Parameter | Required | Description |
|---|---|---|
| `text` | yes | The LLM output to score |
| `context` | no | Ground-truth context (question, retrieved docs, system prompt) |

### Response (after payment)

```json
{
  "sigma": 0.87,
  "coherent": true,
  "flags": [],
  "text_preview": "The quarterly report shows…"
}
```

| Field | Type | Description |
|---|---|---|
| `sigma` | float 0–1 | Coherence score. 1.0 = fully coherent, 0.0 = contradicts context |
| `coherent` | bool | `true` when `sigma >= 0.5` |
| `flags` | string[] | Detected issues: `"hedging"`, `"contradiction"`, `"overconfident"`, `"hallucination_risk"` |
| `text_preview` | string | First 80 chars of scored text (echo for audit) |

---

## x402 pay flow (Solana USDC, no signup)

The endpoint uses [x402](https://x402.org) — HTTP 402 payment required, permissionless, no account.

**Flow:**

1. Call `/check` → receive `HTTP 402` with a `X-Payment-Required` header containing a Solana USDC pay-to address and amount.
2. Send the specified USDC amount to the address on Solana mainnet.
3. Include the transaction signature as `X-Payment-Tx` in a retry of the same request.
4. Receive `HTTP 200` with the JSON result.

**Cost:** 0.001 USDC per call. No subscription, no account, no KYC. Phantom wallet works directly.

Alternatively: buy a credit pack via card at [buy.stripe.com/14AeVf6J2ehZegscnZdEs02](https://buy.stripe.com/14AeVf6J2ehZegscnZdEs02) — €9 for 1000 checks, no account.

---

## Examples

### curl

```bash
# First call — returns 402 with payment details
curl -i "https://swagletz-sigmagate.hf.space/check?text=The+model+said+Paris+is+the+capital+of+Germany&context=What+is+the+capital+of+France?"

# HTTP/1.1 402 Payment Required
# X-Payment-Required: solana:USDC:0.001:RECIPIENT_ADDRESS

# After paying — include tx signature
curl -i \
  -H "X-Payment-Tx: YOUR_SOLANA_TX_SIGNATURE" \
  "https://swagletz-sigmagate.hf.space/check?text=The+model+said+Paris+is+the+capital+of+Germany&context=What+is+the+capital+of+France?"

# {"sigma": 0.12, "coherent": false, "flags": ["contradiction"], "text_preview": "The model said Paris is the capital of Ge…"}
```

### Python (`requests`)

```python
import requests

ENDPOINT = "https://swagletz-sigmagate.hf.space/check"
TX_SIG = "YOUR_SOLANA_TX_SIGNATURE"  # after paying 0.001 USDC

resp = requests.get(
    ENDPOINT,
    params={
        "text": "The treaty was signed in 1847.",
        "context": "The treaty was signed in 1848 according to the official record.",
    },
    headers={"X-Payment-Tx": TX_SIG},
)

if resp.status_code == 402:
    print("Payment required:", resp.headers.get("X-Payment-Required"))
elif resp.ok:
    result = resp.json()
    print(f"sigma={result['sigma']:.2f}  coherent={result['coherent']}  flags={result['flags']}")
    # sigma=0.31  coherent=False  flags=['contradiction']
```

---

## Typical use-cases

- **RAG pipelines:** score each generated answer against retrieved chunks. Drop or flag answers below `sigma < 0.6`.
- **LLM eval:** batch-score a test set without an LLM-as-judge (no model token cost, deterministic rerank).
- **Agent output review:** before an agent posts a public message, score it against the original task context.
- **Hallucination triage:** route low-sigma outputs to a human reviewer instead of the end-user.

---

## What it does NOT replace

The hosted `/check` endpoint does **not** run the open-core structural detectors (secret / injection / PII). For those, use `from guard import guard` locally — it is always free, zero-dependency, and gives identical verdicts offline. Run both if you need full coverage: the open-core gate catches structural threats; the hosted endpoint catches semantic incoherence.

```python
from guard import guard

# Step 1 — structural gate (free, local, deterministic)
v = guard(output)
if not v["safe_to_ship"]:
    raise ValueError(f"blocked: {v['block_reasons']}")

# Step 2 — coherence gate (hosted, probabilistic, pay-per-call)
resp = requests.get(ENDPOINT, params={"text": output, "context": ctx},
                    headers={"X-Payment-Tx": TX_SIG})
result = resp.json()
if not result["coherent"]:
    raise ValueError(f"incoherent: sigma={result['sigma']} flags={result['flags']}")
```

---

## No SLA claim

The hosted endpoint runs on Hugging Face Spaces (free tier). Uptime and latency are best-effort. For production use-cases that need guaranteed availability, run the open-core locally — it is the only part with a latency guarantee (~85µs, no network).

---

Part of [Spektre Labs](https://spektrelabs.org) — coherence-theory research lab. `1 = 1`, made executable.
