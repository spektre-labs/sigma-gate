# σ-gate integrations

Framework-specific wrappers around the zero-dependency `guard` core.
The core is always importable without any extras; each integration lazily
imports its framework and raises a clear `ImportError` with install
instructions if the framework is absent.

---

## LangChain — `integrations/langchain_guard.py`

Requires `langchain-core` (framework-optional, not a hard dependency of σ-gate):

```bash
pip install langchain-core
```

Exposes three objects:

| Name | Type | What it does |
|------|------|--------------|
| `GuardTool` | `BaseTool` | Agent tool — runs `guard(text)` and returns the JSON verdict |
| `guard_runnable` | factory → `RunnableLambda` | LCEL chain step — gates text, raises on block |
| `GuardOutputParser` | `BaseOutputParser` | LCEL output parser — gates LLM output before returning |

### GuardTool — agent tool-belt

```python
from integrations.langchain_guard import GuardTool

tool = GuardTool()

# Direct call
result = tool.run("Here is your key: ghp_16C7e42F292c6912E7710c838347Ae178B4a")
# Returns JSON string:
# {"safe_to_ship": false, "severity": "high", "block_reasons": ["secret[high]: github_pat"], ...}

# Wire into an agent
from langchain_core.agents import AgentExecutor
tools = [GuardTool()]
```

`GuardTool` accepts three inputs (all settable via `tool.run({"text": ..., "block_at": "high"})`):

| Param | Default | Description |
|-------|---------|-------------|
| `text` | — | Text to gate (required) |
| `context` | `""` | Ground-truth context (reserved for hallucination dim) |
| `block_at` | `"medium"` | Severity threshold: `low \| medium \| high \| critical` |

---

### guard_runnable — LCEL chain step

`guard_runnable` is a **factory** (callable); invoke it to get the `RunnableLambda`:

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from integrations.langchain_guard import guard_runnable

llm = ChatOpenAI(model="gpt-4o-mini")
prompt = ChatPromptTemplate.from_messages([("user", "{question}")])

# Gate every LLM response before it reaches the caller.
chain = prompt | llm | (lambda m: m.content) | guard_runnable()

try:
    answer = chain.invoke({"question": "What is 2+2?"})
except ValueError as e:
    print(f"Blocked: {e}")
```

Safe outputs pass through unchanged.  
Blocked outputs raise `ValueError` with severity and reasons:

```
ValueError: guard blocked output [severity=high]: secret[high]: github_pat
```

---

### GuardOutputParser — output parser

Drop-in `BaseOutputParser` replacement that gates before returning the string:

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from integrations.langchain_guard import GuardOutputParser

chain = (
    ChatPromptTemplate.from_messages([("user", "{question}")])
    | ChatOpenAI(model="gpt-4o-mini")
    | GuardOutputParser()            # block_at="medium" by default
)

# Or raise threshold:
chain = prompt | llm | GuardOutputParser(block_at="high")
```

---

### Zero-dep guarantee

The integration imports `guard` (zero-dep) at module load.  
`langchain_core` is imported **only inside functions/classes** — the module is
safe to import in any environment:

```python
# Works fine even without langchain installed:
from integrations.langchain_guard import GuardTool, guard_runnable, GuardOutputParser
# No error. Attempting to *instantiate* them raises ImportError with instructions.
```

---

### Verdict schema

Every guard call returns:

```json
{
  "safe_to_ship": true,
  "severity": "clean | low | medium | high | critical",
  "block_reasons": ["secret[high]: github_pat", "..."],
  "dimensions": {
    "secret":    {"clean": true,  "severity": "clean", "n": 0, "detail": []},
    "injection": {"clean": true,  "severity": "clean", "n": 0, "detail": []},
    "pii":       {"clean": true,  "severity": "clean", "n": 0, "detail": []}
  },
  "block_at": "medium"
}
```
