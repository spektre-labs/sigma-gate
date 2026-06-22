#!/usr/bin/env python3
"""
PROMPTGUARD — deterministinen prompt-injektio / jailbreak -tunnistin. Kolmas AI-putken riski
(hallusinaatio + vuotaneet salaisuudet + INJEKTIO). EI mallia → toistettava, nopea, ei degradoidu.

Tunnistaa yleiset injektio/jailbreak-kuviot agentti-inputissa, RAG-dokumenteissa, työkalu-tuloksissa:
instruktion ohitus, rooli/system-override, data-exfiltraatio, encoded-payload, delimiter-injektio,
"DAN"/jailbreak-persoonat, tool/secret-pyynnöt. Pisteyttää riskin 0..1 + liput.

  check(text) -> {risk, verdict(pass/review/block), flags:[{pattern,severity,match}], n, method}

CLI:  python3 promptguard.py "<text>"   |   python3 promptguard.py < file
"""
from __future__ import annotations
import sys, re, json

PASS_T, BLOCK_T = 0.34, 0.66

# (name, severity, weight, regex) — tunnetut injektio/jailbreak-signaalit
_SIGNALS = [
    ("ignore_instructions", "high", 0.6, r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|the)\b[^.\n]{0,20}\b(instruction|prompt|rule|context|message|direction)s?\b"),
    ("system_prompt_probe", "high", 0.55, r"(?i)\b(reveal|show|print|repeat|output|tell me|what (is|are|was))\b[^.\n]{0,30}\b(system prompt|your (instructions|prompt|rules|system)|initial prompt|the prompt above)\b"),
    ("role_override", "high", 0.55, r"(?i)\b(you are now|from now on,? you|act as|pretend to be|roleplay as|new (role|persona|identity)|simulate (a|an)?)\b[^.\n]{0,40}\b(dan|developer mode|jailbreak|unfiltered|no (restrictions|filter|rules)|do anything now)\b"),
    ("jailbreak_persona", "high", 0.6, r"(?i)\b(dan mode|developer mode enabled|do anything now|stay in character|opposite mode|aim:|jailbroken)\b"),
    ("override_guardrails", "high", 0.55, r"(?i)\b(ignore|bypass|disable|turn off|remove)\b[^.\n]{0,30}\b(safety|guardrail|content policy|filter|moderation|restriction|ethical)s?\b"),
    ("data_exfiltration", "high", 0.5, r"(?i)\b(send|post|exfiltrate|upload|email|forward|leak)\b[^.\n]{0,30}\b(conversation|history|context|secret|api[_ ]?key|credential|env|token|data)\b[^.\n]{0,30}\b(to|http|url|webhook|address)\b"),
    ("tool_secret_request", "med", 0.45, r"(?i)\b(print|reveal|output|give me|return)\b[^.\n]{0,25}\b(environment variable|env var|api key|secret|password|credential|\.env|access token)s?\b"),
    ("delimiter_injection", "med", 0.4, r"(?i)(\b(end of|ignore everything above)\b|-{3,}\s*(system|assistant|user)\s*-{3,}|\[/?(system|inst|s)\]|<\|im_(start|end)\|>|###\s*(system|instruction))"),
    ("instruction_smuggling", "med", 0.4, r"(?i)\b(the (real|actual|true) (task|instruction|goal) is|your (real|actual) (job|task) is|secretly|covertly)\b"),
    ("encoded_payload", "med", 0.35, r"(?i)\b(base64|rot13|hex decode|decode this|reverse the|atob\()\b[^.\n]{0,30}\b(and (then )?(execute|run|follow|do)|instruction|command)\b"),
    ("refusal_suppression", "med", 0.4, r"(?i)\b(do not|don't|never)\b[^.\n]{0,20}\b(refuse|decline|say you can'?t|apologize|warn|mention (you're|that you are) an ai)\b"),
    ("unicode_obfuscation", "low", 0.3, r"[​-‏‪-‮⁠-⁤﻿]"),  # zero-width / bidi control chars
]
_COMPILED = [(n, s, w, re.compile(p)) for n, s, w, p in _SIGNALS]


def _verdict(r: float) -> str:
    return "pass" if r < PASS_T else ("review" if r < BLOCK_T else "block")


def check(text: str, redact: bool = True) -> dict:
    t = text or ""
    flags = []
    score = 0.0
    seen = set()
    for name, sev, weight, rx in _COMPILED:
        m = rx.search(t)
        if not m:
            continue
        if name in seen:
            continue
        seen.add(name)
        score += weight
        snippet = (m.group(0) or "")[:60]
        if name == "unicode_obfuscation":
            snippet = f"<{len(rx.findall(t))} hidden/bidi char(s)>"
        flags.append({"pattern": name, "severity": sev, "match": snippet})
    risk = min(1.0, round(score, 3))
    sev_rank = {"low": 1, "med": 2, "high": 3}
    flags.sort(key=lambda f: -sev_rank.get(f["severity"], 0))
    worst = max((f["severity"] for f in flags), key=lambda s: sev_rank.get(s, 0), default="none")
    return {"risk": risk, "verdict": _verdict(risk), "flags": flags, "n": len(flags),
            "worst": worst, "method": "deterministic-pattern", "clean": len(flags) == 0}


def main():
    text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(check(text), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
