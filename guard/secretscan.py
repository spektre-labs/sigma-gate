#!/usr/bin/env python3
"""
SECRETSCAN — deterministinen vuotaneiden avainten/tokenien skanneri. EI mallia, EI brain-riippuvuutta
→ TOISTETTAVA ja nopea (sama input → sama tulos), halpa (toisin kuin LLM-judge). EI 100% recall:
regex + entropia-heuristiikka voi missata epästandardit/obfuskoidut salaisuudet. Skannaa tekstin/
diffin/koodin tunnettujen provider-avainten kaavoilla + Shannon-entropia korkean-satunnaisuuden salaisuuksille.

Tämä on aito, myytävä dev-tool: "leaked-secret scanner as an API" — sama infra (api_keys + server)
kuin σ-gate, mutta determinist. Toinen tulo-pinta joka ei kaadu jos free-brainit 403:aavat.

  scan(text, redact=True) -> {findings:[{type,severity,match(redacted),line,entropy}], n, worst}

CLI:  python3 secretscan.py < file       # skannaa stdin
      python3 secretscan.py "<text>"
"""
from __future__ import annotations
import sys, re, math

# (name, severity, compiled regex). Kaavat tunnetuille avainmuodoille (2026 yleisimmät).
_PATTERNS = [
    ("aws_access_key_id", "high", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret_access_key", "high", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    ("github_pat", "high", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("github_fine_grained", "high", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    ("github_oauth", "high", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("github_user_to_server", "high", r"\bghu_[A-Za-z0-9]{36}\b"),
    ("github_server_to_server", "high", r"\bghs_[A-Za-z0-9]{36}\b"),
    ("github_refresh", "high", r"\bghr_[A-Za-z0-9]{36}\b"),
    ("openai_key", "high", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    ("anthropic_key", "high", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("google_api_key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack_token", "high", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ("slack_webhook", "med", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
    ("stripe_secret", "high", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
    ("stripe_test", "low", r"\b(?:sk|rk)_test_[0-9A-Za-z]{24,}\b"),
    ("twilio_sid", "med", r"\bAC[0-9a-fA-F]{32}\b"),
    ("sendgrid_key", "high", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("private_key_block", "high", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("jwt", "med", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("gitlab_pat", "high", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ("npm_token", "high", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("hf_token", "high", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("databricks_pat", "high", r"\bdapi[a-fA-F0-9]{30,}\b"),
    ("azure_storage_key", "high", r"(?i)accountkey=([A-Za-z0-9/+=]{88})"),
    # PEM private keys incl. PKCS#8 ENCRYPTED (RFC 5958). Ed25519 uses the bare/ OPENSSH header → already covered.
    ("private_key_block", "high", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    # seed phrase: STRONG context only (not common words) + valid BIP39 lengths (12/15/18/21/24)
    ("seed_phrase", "high", r"(?i)\b(?:[a-z]{3,8}\s+){11}(?:[a-z]{3,8})(?:(?:\s+[a-z]{3,8}){3}){0,4}\b"),
    ("generic_secret_assign", "med", r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[=:]\s*['\"]([^'\"\s]{20,})['\"]"),
]
# drop the duplicate generic PEM line above's older variant by de-duping on name (last wins)
_PATTERNS = list({n: (n, s, p) for n, s, p in _PATTERNS}.values())
_COMPILED = [(n, s, re.compile(p)) for n, s, p in _PATTERNS]
# STRONG seed context only — removed common English words (able/about/wallet) that caused false positives
_BIP39_HINT = re.compile(r"(?i)\b(mnemonic|seed phrase|recovery phrase|private key|secret phrase|bip-?39)\b")
_BIP39_LENGTHS = {12, 15, 18, 21, 24}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 2)


def _redact(m: str) -> str:
    if len(m) <= 8:
        return m[0] + "***"
    return m[:4] + "…" + m[-4:] + f"({len(m)})"


def scan(text: str, redact: bool = True) -> dict:
    t = text or ""
    lines = t.splitlines()
    findings = []
    seen = set()
    for name, sev, rx in _COMPILED:
        for m in rx.finditer(t):
            raw = m.group(1) if m.groups() else m.group(0)
            # seed-phrase: require STRONG context word nearby AND a valid BIP39 word count (12/15/18/21/24)
            if name == "seed_phrase":
                if not _BIP39_HINT.search(t):
                    continue
                if len(raw.split()) not in _BIP39_LENGTHS:
                    continue
            key = (name, raw)
            if key in seen:
                continue
            seen.add(key)
            ln = t[:m.start()].count("\n") + 1
            ent = _entropy(raw)
            # entropy gate for generic matches — 4.0 char-entropy cuts prose/weak-password false positives
            if name == "generic_secret_assign" and ent < 4.0:
                continue
            findings.append({"type": name, "severity": sev,
                             "match": _redact(raw) if redact else raw,
                             "line": ln, "entropy": ent})
    sev_rank = {"low": 1, "med": 2, "high": 3}
    findings.sort(key=lambda f: (-sev_rank.get(f["severity"], 0), f["line"]))
    worst = max((f["severity"] for f in findings), key=lambda s: sev_rank.get(s, 0), default="none")
    return {"findings": findings, "n": len(findings), "worst": worst,
            "lines_scanned": len(lines), "clean": len(findings) == 0}


_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".lock", ".min.js", ".map"}


def scan_paths(root: str, max_file_bytes: int = 2_000_000) -> dict:
    """Walk a directory, scan each text file. Returns aggregated findings with file paths.
    For CI: exit non-zero if any high-severity leak. No deps."""
    import os
    out = []
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if any(fn.endswith(e) for e in _SKIP_EXT):
                continue
            fp = os.path.join(dp, fn)
            try:
                if os.path.getsize(fp) > max_file_bytes:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read()
            except Exception:
                continue
            r = scan(txt)
            for finding in r["findings"]:
                out.append({**finding, "file": os.path.relpath(fp, root)})
    sev_rank = {"low": 1, "med": 2, "high": 3}
    out.sort(key=lambda f: (-sev_rank.get(f["severity"], 0), f.get("file", "")))
    worst = max((f["severity"] for f in out), key=lambda s: sev_rank.get(s, 0), default="none")
    return {"findings": out, "n": len(out), "worst": worst, "clean": len(out) == 0, "root": root}


def main():
    import json
    args = sys.argv[1:]
    if args and args[0] in ("--path", "-p"):
        target = args[1] if len(args) > 1 else "."
        res = scan_paths(target)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        # CI semantics: high-severity leak → non-zero exit
        sys.exit(2 if res["worst"] == "high" else 0)
    text = " ".join(args) if args else sys.stdin.read()
    print(json.dumps(scan(text), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
