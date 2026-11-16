"""Explainable, offline rules for training/demo email analysis."""

from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse


SUSPICIOUS_PHRASES = (
    "account will be suspended",
    "immediate action required",
    "urgent action required",
    "click here to unlock",
    "wire transfer",
    "gift card",
    "you have won",
)

CREDENTIAL_REQUEST_PATTERNS = (
    re.compile(r"\b(?:verify|confirm|validate)\s+(?:(?:your|their|the)\s+)?(?:account\s+)?password\b", re.I),
    re.compile(r"\bpassword\s+verification\b", re.I),
    re.compile(r"\b(?:enter|provide|share|send)\s+(?:(?:your|their|the)\s+)?(?:account\s+)?(?:password|credentials)\b", re.I),
    re.compile(r"\b(?:verify|confirm)\s+(?:(?:your|their|the)\s+)?credentials\b", re.I),
    re.compile(r"\b(?:sign in|log in)\s+to\s+(?:verify|confirm|secure)\b", re.I),
)

KNOWN_BRANDS = {
    "amazon": "amazon.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "t.co",
    "tinyurl.com",
}

URL_PATTERN = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
EMAIL_PATTERN = re.compile(r"(?i)^[^@\s<>]+@([^@\s<>]+)$")
LEET_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


def _domain_from_email(sender: str) -> str | None:
    sender = sender.strip()
    if "<" in sender and sender.endswith(">"):
        sender = sender.rsplit("<", 1)[1][:-1].strip()
    match = EMAIL_PATTERN.fullmatch(sender)
    return match.group(1).lower().rstrip(".") if match else None


def _brand_impersonation(domain: str) -> tuple[str, str] | None:
    """Return a known brand and official domain when a host imitates that brand."""
    host = domain.lower().rstrip(".")
    labels = host.split(".")
    for brand, official_domain in KNOWN_BRANDS.items():
        if host == official_domain or host.endswith(f".{official_domain}"):
            continue

        for label in labels[:-1]:
            normalized = label.translate(LEET_TRANSLATION).replace("-", "")
            similarity = SequenceMatcher(None, normalized, brand).ratio()
            if brand in normalized or similarity >= 0.78:
                return brand, official_domain
    return None


def _sender_findings(sender: str) -> tuple[list[str], str | None]:
    domain = _domain_from_email(sender)
    if domain is None:
        return ["Sender address is not in a recognizable email format."], None

    impersonation = _brand_impersonation(domain)
    if impersonation is None:
        return [], None

    brand, official_domain = impersonation
    return [
        f"Sender domain '{domain}' imitates {brand.title()}; the official domain is "
        f"'{official_domain}'."
    ], brand


def _url_findings(text: str) -> tuple[list[str], int, set[str]]:
    findings: list[str] = []
    points = 0
    impersonated_brands: set[str] = set()

    for candidate in URL_PATTERN.findall(text):
        url_text = candidate.rstrip(".,;:!?)]}")
        normalized = f"http://{url_text}" if url_text.lower().startswith("www.") else url_text
        try:
            parsed = urlparse(normalized)
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host:
            continue

        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            findings.append(f"URL uses a literal IP address ({host}); do not open it.")
            points += 22
            continue

        impersonation = _brand_impersonation(host)
        if impersonation:
            brand, official_domain = impersonation
            findings.append(
                f"URL host '{host}' imitates {brand.title()}; the official domain is "
                f"'{official_domain}'. Do not open it."
            )
            points += 32
            impersonated_brands.add(brand)

        if parsed.scheme == "http":
            findings.append(f"URL uses unencrypted HTTP ({host}); do not open it.")
            points += 8
        if host in SHORTENER_DOMAINS:
            findings.append(f"URL uses the link-shortener domain '{host}'; destination is obscured.")
            points += 15
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(f"URL uses an internationalized/punycode domain ({host}).")
            points += 15

    return findings, points, impersonated_brands


def analyze_email(sender: str, subject: str, body: str) -> dict:
    """Return a bounded risk score, verdict, and human-readable rule findings."""
    findings: list[str] = []
    points = 0
    searchable_text = f"{subject}\n{body}"
    searchable_lower = searchable_text.lower()

    matched_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in searchable_lower]
    for phrase in matched_phrases:
        findings.append(f"Pressure or social-engineering language detected: “{phrase}”.")
    points += min(len(matched_phrases), 2) * 12

    if re.search(r"\bverify\s+your\s+(?:[a-z0-9-]+\s+){0,3}account\b", searchable_text, re.I):
        findings.append("Account-verification language requests action on an account.")
        points += 12

    if any(pattern.search(searchable_text) for pattern in CREDENTIAL_REQUEST_PATTERNS):
        findings.append("Message requests password or credential verification/entry.")
        points += 30

    sender_findings, sender_brand = _sender_findings(sender)
    findings.extend(sender_findings)
    if sender_brand:
        points += 32

    url_findings, url_points, url_brands = _url_findings(searchable_text)
    findings.extend(url_findings)
    points += url_points

    if sender_brand and sender_brand in url_brands:
        findings.append(
            f"Sender domain and URL both imitate {sender_brand.title()}, reinforcing a "
            "coordinated impersonation pattern."
        )
        points += 15

    score = min(points, 100)
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 25 else "Clean"
    if not findings:
        findings.append("No configured warning rules matched; this does not guarantee safety.")

    return {"score": score, "verdict": verdict, "reasons": findings}
