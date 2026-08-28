#!/usr/bin/env python3
"""AI-assisted firmware string review.

Extracts printable strings from a flash dump, runs fast local heuristics for
obvious secrets (API keys, private keys, embedded creds), then optionally
sends the strings to an LLM (OpenAI or Anthropic) for a deeper security
review. Falls back to local-only if no API key is set.

Setup:
    pip install openai anthropic         # whichever provider you use
    export OPENAI_API_KEY=sk-...
    # or
    export ANTHROPIC_API_KEY=sk-ant-...

Usage:
    python3 tools/llm_firmware_review.py flash.bin --provider openai
    python3 tools/llm_firmware_review.py strings.txt --provider anthropic
    python3 tools/llm_firmware_review.py flash.bin --provider heuristic
"""
import argparse
import os
import re
import sys
from pathlib import Path


STRINGS_RE = re.compile(rb"[\x20-\x7e]{%d,}" % 6)

SECRETS_RE = [
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(rb"sk-[A-Za-z0-9]{20,}"), "OpenAI / Stripe key"),
    (re.compile(rb"sk-ant-[A-Za-z0-9\-]{20,}"), "Anthropic key"),
    (re.compile(rb"ghp_[A-Za-z0-9]{36}"), "GitHub PAT"),
    (re.compile(rb"xox[abop]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----"), "Private key"),
    (re.compile(rb"(?i)password\s*[:=]\s*\S+"), "Possible password literal"),
    (re.compile(rb"(?i)api[_-]?key\s*[:=]\s*\S+"), "Possible API key literal"),
    (re.compile(rb"https?://[^\s/:@]*:[^\s/@]+@[^\s/]+"), "URL with embedded creds"),
    (re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "Hard-coded IP address"),
    (re.compile(rb"(?i)(telnet|ftp)://[^\s]+"), "Plaintext protocol URL"),
]


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [s.decode("latin-1", "replace") for s in pat.findall(data)]


def looks_like_strings_file(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if text.count("\n") < 5:
        return False
    head = text[:1000]
    return all(c.isprintable() or c in "\n\r\t" for c in head)


def local_heuristics(strings: list[str]) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for s in strings:
        sb = s.encode("latin-1", "replace")
        for pat, label in SECRETS_RE:
            if pat.search(sb):
                findings.append((label, s[:160]))
    return findings


PROMPT = """You are a senior security researcher reviewing strings extracted from \
an ESP32 / ESP8266 firmware image. The device is a candidate for authorized \
hardware audit. Identify and explain:

- Hardcoded secrets (API keys, tokens, private keys, passwords)
- Suspicious URLs (telemetry, debug endpoints, hardcoded hosts)
- Insecure defaults (disabled TLS, weak crypto, plaintext protocols)
- Hardcoded credentials, certificates, or tokens
- PII or device-specific identifiers
- Anything that looks like a backdoor, kill switch, or hidden command
- Bypasses around secure boot, flash encryption, or signing

Cite the exact string you are flagging. If a finding is borderline, say so. \
If nothing stands out, say so explicitly. Be terse — bullet points, not prose.

Strings:
{strings}
"""


def call_openai(strings: list[str], model: str = "gpt-4o-mini") -> str:
    from openai import OpenAI  # type: ignore
    client = OpenAI()
    sample = "\n".join(strings[:600])
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": PROMPT.format(strings=sample)}],
        temperature=0.1,
        max_tokens=1500,
    )
    return resp.choices[0].message.content or ""


def call_anthropic(strings: list[str], model: str = "claude-3-5-sonnet-latest") -> str:
    import anthropic  # type: ignore
    client = anthropic.Anthropic()
    sample = "\n".join(strings[:600])
    msg = client.messages.create(
        model=model,
        max_tokens=1500,
        messages=[{"role": "user", "content": PROMPT.format(strings=sample)}],
    )
    return msg.content[0].text


def main() -> int:
    p = argparse.ArgumentParser(description="AI-assisted firmware string review")
    p.add_argument("input", help="path to .bin flash dump or pre-extracted strings .txt")
    p.add_argument(
        "--provider",
        choices=["openai", "anthropic", "heuristic"],
        default="heuristic",
        help="LLM provider for the deep review pass (default: local heuristics only)",
    )
    p.add_argument("--min-len", type=int, default=6)
    args = p.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        sys.exit(f"[-] File not found: {inp}")
    data = inp.read_bytes()

    if looks_like_strings_file(data):
        strings = [ln for ln in data.decode("utf-8").splitlines() if len(ln) >= args.min_len]
    else:
        strings = extract_strings(data, args.min_len)

    print(f"[+] {len(strings)} strings (min len {args.min_len}) from {inp.name}")

    findings = local_heuristics(strings)
    if findings:
        print(f"\n[!] {len(findings)} local-heuristic match(es):")
        seen = set()
        for label, s in findings:
            key = (label, s)
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{label}]  {s}")
    else:
        print("[+] No local-heuristic matches.")

    if args.provider == "heuristic":
        return 0

    has_key = (
        (args.provider == "openai" and os.environ.get("OPENAI_API_KEY"))
        or (args.provider == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"))
    )
    if not has_key:
        sys.exit(
            f"[-] {args.provider} selected but no API key env var found "
            f"(OPENAI_API_KEY / ANTHROPIC_API_KEY)"
        )

    print(f"\n[+] Sending to {args.provider} for deeper review ...")
    try:
        if args.provider == "openai":
            result = call_openai(strings)
        else:
            result = call_anthropic(strings)
    except Exception as e:
        sys.exit(f"[-] LLM call failed: {e}")

    print("\n=== LLM REVIEW ===\n")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
