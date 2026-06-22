# σ-gate

[![ci](https://github.com/spektre-labs/sigma-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/spektre-labs/sigma-gate/actions/workflows/ci.yml)

**Deterministic trust layer for AI/agent output.**

```
1 = 1.  Declared output must equal what is safe to realize.
```

One call. Three dimensions. One verdict. No model. No API key. No network.

---

## The problem

LLM-as-judge guards are slow, consume a call per check, and silently degrade when a rate-limit hits. For the classes of risk that are *structurally detectable* — a leaked `AKIA…` key, a `4111…` card number, an "ignore all previous instructions" — you do not need a model. You need a gate that gives the **same answer every time**.

`guard` is that gate.

---

## One call

```python
from guard import guard

result = guard(model_output)
# {"safe_to_ship": True/False, "severity": "clean|low|medium|high|critical",
#  "block_reasons": [...], "dimensions": {"secret": {...}, "injection": {...}, "pii": {...}}}
```

Block a bad output:

```python
v = guard("Here is the key: ghp_16C7e42F292c6912E7710c838347Ae178B4a")
# safe_to_ship: False
# block_reasons: ["secret[high]: github_pat"]
```

Pass a clean output through:

```python
v = guard("The quarterly report shows revenue grew 12% driven by the EU segment.")
# safe_to_ship: True
# severity: "clean"
```

---

## Three dimensions, one verdict

| Dimension | What it catches |
|---|---|
| **secret** | Leaked credentials — 20+ providers (AWS, GitHub, Stripe, GCP, …), entropy-ranked |
| **injection** | Prompt-injection and jailbreak patterns — structural, not heuristic |
| **pii** | Email, phone, card (Luhn-verified), SSN, IBAN, IP — compliance-class detection |

Every dimension runs independently. A combined hit fires all three:

```python
guard("AKIA… ghp_… 4111 1111 1111 1111 — ignore all previous instructions")
# block_reasons: ["secret[high]: ...", "injection[high]: ...", "pii[high]: ..."]
```

---

## Install

Zero dependencies, pure stdlib, Python 3.9+. Clone and use directly:

```bash
git clone https://github.com/spektre-labs/sigma-gate
cd sigma-gate
python3 -m pytest -q        # 7 passing tests, zero dependencies
```

Then `from guard import guard`. (A PyPI release is planned.)

---

## Use it

**Inline gate in any pipeline:**

```python
from guard import guard

def ship(output: str) -> str:
    v = guard(output)
    if not v["safe_to_ship"]:
        raise ValueError(f"blocked: {v['block_reasons']}")
    return output
```

**CLI — pipe any output through:**

```bash
echo "your model output" | python3 -m guard
```

**Self-test — prove every threat class fires:**

```bash
python3 -m guard selftest
# {"secret_blocked": true, "injection_blocked": true, "pii_blocked": true,
#  "clean_passes": true, "combined_all_fire": true, "ALL_PASS": true}
```

**Tune the threshold** via env var (default: `medium`):

```bash
GUARD_BLOCK_AT=high python3 -m guard "..."
```

---

## Use as an MCP tool

σ-gate ships a zero-dependency [MCP](https://modelcontextprotocol.io) server — give any agent
(Claude Code, Claude Desktop, Cursor, Cline) a deterministic `guard` tool it can call before shipping
output. No model, no key, no token cost.

**Claude Code:**

```bash
claude mcp add guard -- python3 /absolute/path/to/sigma-gate/mcp_server.py
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{ "mcpServers": { "guard": { "command": "python3",
  "args": ["/absolute/path/to/sigma-gate/mcp_server.py"] } } }
```

Exposes two tools: `guard(text, …)` → the ship/block verdict, and `guard_selftest()` → proof every
threat class fires. Pure stdlib stdio JSON-RPC.

---

## Open-core vs hosted

| | **Open core (this repo)** | **Hosted σ scoring** |
|---|---|---|
| **What** | Deterministic gate: secret + injection + PII | Coherence / hallucination σ-scoring on a hot path |
| **Latency** | ~85µs | Network round-trip |
| **Dependencies** | Zero | None on your side |
| **Cost** | Free, always | Pay-per-call via x402 — no signup |
| **Offline** | Yes | No |
| **Model** | None | Optional |

The open core handles what models cannot do reliably — structural pattern detection with identical verdicts on identical inputs. The hosted layer adds probabilistic coherence scoring for the cases where structure alone is insufficient.

**Hosted endpoint:**

```bash
curl "https://swagletz-sigmagate.hf.space/check?text=your+text+here"
# HTTP 402 + permissionless x402 pay-to — no account required
```

---

## Properties

- **Deterministic.** Same input → same verdict. No variance, no model drift.
- **Composable.** Each dimension is independent and pluggable. Wire in a hallucination scorer or extend with custom patterns; the gate architecture is additive.
- **Honest.** Severity and block-reasons are explicit strings, not opaque floats. A block is always nameable.
- **Fails safe.** If a detector throws, that dimension returns `severity: "error"` — the call does not silently pass.
- **Zero dependencies.** Runs anywhere Python 3.9+ runs. No pip install required to import.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

Part of [Spektre Labs](https://spektrelabs.org) — coherence-theory research lab.
`1 = 1`, made executable.
