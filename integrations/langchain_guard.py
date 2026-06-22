"""
langchain_guard — σ-gate LangChain integration.

Provides:
  GuardTool       — langchain_core BaseTool; call guard(text) from any agent tool-belt.
  guard_runnable  — RunnableLambda that gates text in an LCEL chain.
  GuardOutputParser — BaseOutputParser that raises on blocked output.

All langchain_core imports are lazy so the core guard library stays zero-dep.
If langchain-core is not installed the module imports cleanly; attempting to
*use* either component raises ImportError with install instructions.

Usage::

    from integrations.langchain_guard import GuardTool, guard_runnable
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Make guard importable when used from outside the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from guard import guard as _guard  # noqa: E402  (zero-dep core, always available)

_LC_INSTALL_MSG = (
    "langchain-core is required for this integration.\n"
    "Install it with:  pip install langchain-core"
)


def _require_lc() -> Any:
    """Return the langchain_core module or raise a clear ImportError."""
    try:
        import langchain_core  # noqa: F401
        return langchain_core
    except ModuleNotFoundError:
        raise ImportError(_LC_INSTALL_MSG) from None


# ---------------------------------------------------------------------------
# GuardTool
# ---------------------------------------------------------------------------

def _make_guard_tool_class():
    """Build and return GuardTool (deferred so the class body doesn't fail at import)."""
    _require_lc()
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, Field

    class _GuardInput(BaseModel):
        text: str = Field(..., description="The text/output to gate before shipping.")
        context: str = Field("", description="Optional ground-truth context (reserved for hallucination dim).")
        block_at: str = Field("medium", description="Severity threshold: low | medium | high | critical.")

    class GuardTool(BaseTool):
        """
        Deterministic pre-ship trust gate for AI/agent output.

        Runs leaked-secret detection, prompt-injection / jailbreak detection,
        and PII / compliance detection — one call, no model, no API key.

        Returns the full guard verdict as a JSON string so the agent can decide
        what to do with the result.
        """

        name: str = "guard"
        description: str = (
            "Gate text before shipping. Detects leaked secrets, prompt injection, "
            "and PII. Returns a JSON verdict with safe_to_ship (bool), severity, "
            "and block_reasons. No model, no API key, deterministic."
        )
        args_schema: type = _GuardInput

        def _run(
            self,
            text: str,
            context: str = "",
            block_at: str = "medium",
            **_: Any,
        ) -> str:
            verdict = _guard(text, context=context, block_at=block_at)
            return json.dumps(verdict, ensure_ascii=False)

        async def _arun(
            self,
            text: str,
            context: str = "",
            block_at: str = "medium",
            **_: Any,
        ) -> str:
            # Guard is CPU-only / no I/O — just call sync version.
            return self._run(text, context=context, block_at=block_at)

    return GuardTool


class GuardTool:
    """
    Lazy proxy for the real GuardTool (which requires langchain-core).

    Instantiating this class raises ImportError with install instructions if
    langchain-core is not present; otherwise returns a fully wired BaseTool.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        RealClass = _make_guard_tool_class()
        return RealClass(*args, **kwargs)


# ---------------------------------------------------------------------------
# guard_runnable  (RunnableLambda)
# ---------------------------------------------------------------------------

def _make_guard_runnable():
    """Return a RunnableLambda that gates text, passing it through or raising."""
    _require_lc()
    from langchain_core.runnables import RunnableLambda

    def _gate(text: str) -> str:
        verdict = _guard(text)
        if not verdict["safe_to_ship"]:
            raise ValueError(
                f"guard blocked output [severity={verdict['severity']}]: "
                + "; ".join(verdict["block_reasons"])
            )
        return text

    return RunnableLambda(_gate)


def _guard_runnable_proxy() -> Any:
    """
    Lazy factory: call this to get the RunnableLambda.

    Raises ImportError (with install instructions) if langchain-core is absent.
    """
    return _make_guard_runnable()


# guard_runnable is intentionally a *callable* that produces the Runnable so the
# module import stays clean without langchain-core.  Users call it in their chain:
#   chain = llm | guard_runnable()
guard_runnable = _guard_runnable_proxy


# ---------------------------------------------------------------------------
# GuardOutputParser
# ---------------------------------------------------------------------------

def _make_guard_output_parser_class():
    """Build and return GuardOutputParser."""
    _require_lc()
    from langchain_core.output_parsers import BaseOutputParser

    class GuardOutputParser(BaseOutputParser):
        """
        Output parser that runs guard() on the raw LLM string before returning it.

        Raises ValueError if the output is blocked, passing through safe text unchanged.

        Compatible with LCEL::

            chain = prompt | llm | GuardOutputParser()
        """

        block_at: str = "medium"

        @property
        def _type(self) -> str:
            return "guard_output_parser"

        def parse(self, text: str) -> str:
            verdict = _guard(text, block_at=self.block_at)
            if not verdict["safe_to_ship"]:
                raise ValueError(
                    f"guard blocked [severity={verdict['severity']}]: "
                    + "; ".join(verdict["block_reasons"])
                )
            return text

    return GuardOutputParser


class GuardOutputParser:
    """Lazy proxy for GuardOutputParser (requires langchain-core)."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        RealClass = _make_guard_output_parser_class()
        return RealClass(*args, **kwargs)


__all__ = ["GuardTool", "guard_runnable", "GuardOutputParser"]
