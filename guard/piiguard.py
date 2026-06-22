#!/usr/bin/env python3
"""
PIIGUARD — deterministinen PII / compliance -tunnistin. Neljäs pre-ship-riski: AI-tuotos vuotaa
henkilötietoja (GDPR/CCPA). EI mallia → toistettava, nopea. Luhn-validointi korteille (vähemmän
false-positiveja). Redaktoi löydöt.

Tunnistaa: email, puhelin (E.164/US), luottokortti (Luhn-validoitu), US SSN, IBAN, IPv4, IPv6.

  scan(text, redact=True) -> {findings:[{type,severity,match,line}], n, worst, clean, counts}

CLI:  python3 piiguard.py "<text>"  |  python3 piiguard.py < file
"""
from __future__ import annotations
import sys, re, json

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?\d{3}[\s.\-]?\d{3,4}[\s.\-]?\d{0,4}(?!\d)")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.I)


def _luhn(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    s, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def _redact(m: str, keep: int = 2) -> str:
    digits = [c for c in m if c.isalnum()]
    if len(digits) <= keep * 2:
        return "*" * len(m)
    return m[:keep] + "…" + m[-keep:]


def scan(text: str, redact: bool = True) -> dict:
    t = text or ""
    findings = []
    seen = set()
    claimed = []   # (start, end) spans claimed by higher-confidence types → phone skips these

    def _overlaps(a, b):
        return not (a[1] <= b[0] or b[1] <= a[0])

    def add(kind, sev, raw, span):
        if (kind, raw) in seen:
            return
        seen.add((kind, raw))
        claimed.append(span)
        ln = t[:span[0]].count("\n") + 1
        findings.append({"type": kind, "severity": sev,
                         "match": _redact(raw) if redact else raw, "line": ln})

    # high-confidence, structured types first (they claim their character spans)
    for m in _EMAIL.finditer(t):
        add("email", "low", m.group(0), m.span())   # common in legit output → low (doesn't auto-block ship)
    for m in _SSN.finditer(t):
        add("us_ssn", "high", m.group(0), m.span())
    for m in _IBAN.finditer(t):
        add("iban", "high", m.group(0), m.span())
    for m in _CARD.finditer(t):
        if _luhn(m.group(0)):                # only flag Luhn-valid → cuts false positives
            add("credit_card", "high", m.group(0), m.span())
    for m in _IPV4.finditer(t):
        add("ipv4", "low", m.group(0), m.span())
    for m in _IPV6.finditer(t):
        add("ipv6", "low", m.group(0), m.span())
    # phone LAST and only on unclaimed regions (avoids flagging card/IP/SSN digit fragments)
    for m in _PHONE.finditer(t):
        if any(_overlaps(m.span(), c) for c in claimed):
            continue
        digits = re.sub(r"\D", "", m.group(0))
        if 7 <= len(digits) <= 15:
            add("phone", "low", m.group(0).strip(), m.span())

    sev_rank = {"low": 1, "med": 2, "high": 3}
    findings.sort(key=lambda f: (-sev_rank.get(f["severity"], 0), f["line"]))
    worst = max((f["severity"] for f in findings), key=lambda s: sev_rank.get(s, 0), default="none")
    counts = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    return {"findings": findings, "n": len(findings), "worst": worst,
            "clean": len(findings) == 0, "counts": counts}


def main():
    text = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(scan(text), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
