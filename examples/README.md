# examples/

Three ready-to-run patterns for wiring σ-gate into your stack.
All use only the public `guard` API and Python stdlib — zero extra dependencies.

---

## inline_gate.py

Gate a function's return value; raise on unsafe output.

```python
from guard import guard

class UnsafeOutputError(ValueError): ...

def gated(fn=None, *, block_at="medium"):
    """Decorator — raises UnsafeOutputError if the return value is blocked."""
    ...

@gated
def produce() -> str:
    return model_output   # blocked if it contains secrets / injection / PII

@gated(block_at="high")
def produce_lenient() -> str:
    return model_output   # only blocks high/critical findings
```

```bash
python3 examples/inline_gate.py
```

---

## agent_middleware.py

Model-agnostic wrapper that gates any LLM call before returning the response.
Works identically with OpenAI, Anthropic, or any callable that returns a string.

```python
from guard import guard

class GatedLLM:
    def __init__(self, call: Callable[[str], str], block_at="medium", context=""):
        ...
    def complete(self, prompt: str) -> str:
        raw = self._call(prompt)
        result = guard(raw, block_at=self._block_at)
        if not result["safe_to_ship"]:
            raise BlockedResponseError(result["block_reasons"], ...)
        return raw

# OpenAI
import openai
llm = GatedLLM(
    lambda prompt: openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    ).choices[0].message.content
)

# Anthropic
import anthropic
client = anthropic.Anthropic()
llm = GatedLLM(
    lambda prompt: client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    ).content[0].text
)

text = llm.complete("Summarise the document.")  # raises if model leaks secrets
```

```bash
python3 examples/agent_middleware.py
```

---

## ci_gate.py

Scan a file or stdin; exit nonzero if unsafe. Drop into any pre-commit hook or CI step.

```bash
# scan a file
python3 examples/ci_gate.py generated_output.txt

# scan stdin
echo "model output here" | python3 examples/ci_gate.py

# only block high/critical (let medium through)
python3 examples/ci_gate.py --block-at high generated_output.txt

# full JSON verdict
python3 examples/ci_gate.py --json generated_output.txt

# quiet — exit code only (for scripts)
python3 examples/ci_gate.py --quiet generated_output.txt && deploy.sh
```

**Exit codes:** `0` = safe, `1` = blocked, `2` = usage/IO error.

**Pre-commit hook** (`.git/hooks/pre-commit`):

```bash
#!/usr/bin/env bash
# Gate any generated files before commit.
for f in generated/*.txt; do
    python3 examples/ci_gate.py --quiet "$f" || { echo "σ-gate blocked $f"; exit 1; }
done
```

---

## API reference

```python
from guard import guard

result = guard(text, context="", block_at="medium")
# {
#   "safe_to_ship": True | False,
#   "severity":     "clean" | "low" | "medium" | "high" | "critical",
#   "block_reasons": ["secret[high]: github_pat", ...],
#   "dimensions":   {"secret": {...}, "injection": {...}, "pii": {...}},
#   "block_at":     "medium"
# }
```

`block_at` (default `medium`): severity at which to flip `safe_to_ship` to `False`.
Override globally via env var: `GUARD_BLOCK_AT=high`.
