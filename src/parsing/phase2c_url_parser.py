"""
Phase 2C URL Parser and Normalization Module.

Dedicated Phase 2C parser derived from historical phase2b_common.py with
authorized fixes:
1. Frozen PSL path anchored relative to repository root with fail-loud SHA-256 verification.
2. IP literal detection (IPv4 and IPv6) prior to IDNA encoding.

All other normalization rules, parse statuses, and site key definitions are strictly preserved.
"""
from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna
import pandas as pd
import tldextract


# Find repository root (3 levels up from src/parsing/phase2c_url_parser.py)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PSL_PATH = REPO_ROOT / "data/raw/frozen_resources/public_suffix_list/public_suffix_list_2026-08-17.dat"
EXPECTED_PSL_HASH = "155b43d46932e933f622365225e7861288c36a45380b1f7d00b3d09748926226"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Fail-loud check for frozen PSL file presence and hash
if not PSL_PATH.exists():
    raise RuntimeError(f"Phase-2C frozen PSL file missing at: {PSL_PATH}")

actual_psl_hash = sha256_file(PSL_PATH)
if actual_psl_hash != EXPECTED_PSL_HASH:
    raise RuntimeError(
        f"Phase-2C frozen PSL SHA-256 mismatch! Expected {EXPECTED_PSL_HASH}, got {actual_psl_hash}"
    )

EXTRACT_ICANN = tldextract.TLDExtract(
    suffix_list_urls=(PSL_PATH.resolve().as_uri(),),
    cache_dir=None,
    fallback_to_snapshot=False,
    include_psl_private_domains=False,
)
EXTRACT_PRIVATE = tldextract.TLDExtract(
    suffix_list_urls=(PSL_PATH.resolve().as_uri(),),
    cache_dir=None,
    fallback_to_snapshot=False,
    include_psl_private_domains=True,
)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}


def parse_url(raw: object) -> dict:
    if not isinstance(raw, str) or not raw.strip():
        return {"parse_status": "MISSING_URL"}
    value = raw.strip()
    try:
        first = urlsplit(value)
        missing_scheme = not first.scheme
        parts = urlsplit("//" + value) if missing_scheme else first
    except Exception:
        return {"parse_status": "MALFORMED_URL"}
    scheme = parts.scheme.lower()
    host_raw = parts.hostname
    if not host_raw:
        return {
            "parse_status": "MISSING_HOST",
            "scheme": scheme,
            "path": parts.path,
            "query": parts.query,
            "fragment": parts.fragment,
        }
    host_raw = host_raw.rstrip(".").lower()

    # IP detection BEFORE IDNA encoding (handles both IPv4 and IPv6 literals)
    is_ip = False
    private_ip = False
    clean_host = host_raw.strip("[]")
    try:
        ip = ipaddress.ip_address(clean_host)
        is_ip = True
        private_ip = bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        host_ascii = ip.compressed
    except ValueError:
        # Not a valid IP literal -> attempt IDNA UTS-46 STD3 normalization
        try:
            host_ascii = idna.encode(host_raw, uts46=True, std3_rules=True).decode("ascii").lower()
        except Exception:
            return {
                "parse_status": "MALFORMED_IDN_HOST",
                "scheme": scheme,
                "hostname_raw": host_raw,
                "path": parts.path,
                "query": parts.query,
                "fragment": parts.fragment,
            }

    if is_ip:
        site_icann = site_private = host_ascii
        suffix_icann = suffix_private = subdomain = ""
        private_suffix = False
    else:
        ei, ep = EXTRACT_ICANN(host_ascii), EXTRACT_PRIVATE(host_ascii)
        site_icann = ei.top_domain_under_public_suffix or ""
        site_private = ep.top_domain_under_public_suffix or ""
        suffix_icann, suffix_private = ei.suffix or "", ep.suffix or ""
        subdomain = ep.subdomain or ""
        private_suffix = bool(getattr(ep, "is_private", False))

    try:
        port = parts.port
    except ValueError:
        port = None
        status = "MALFORMED_PORT"
    else:
        unsupported = bool(scheme and scheme not in {"http", "https"})
        local = private_ip or host_ascii == "localhost" or (not is_ip and "." not in host_ascii)
        if unsupported:
            status = "UNSUPPORTED_SCHEME"
        elif local:
            status = "LOCAL_OR_PRIVATE_HOST"
        elif missing_scheme:
            status = "MISSING_SCHEME_RECOVERABLE"
        elif is_ip:
            status = "VALID_IP_HOST_URL"
        elif not site_private:
            status = "MALFORMED_OR_NONPUBLIC_DNS_HOST"
        elif private_suffix:
            status = "VALID_PRIVATE_SUFFIX_URL"
        else:
            status = "VALID_PUBLIC_DNS_URL"

    return {
        "parse_status": status,
        "scheme": scheme,
        "hostname_raw": host_raw,
        "hostname_ascii": host_ascii,
        "is_ip": is_ip,
        "is_private_ip": private_ip,
        "public_suffix_icann": suffix_icann,
        "public_suffix_private": suffix_private,
        "site_key_icann": site_icann,
        "site_key_private": site_private,
        "is_private_suffix": private_suffix,
        "subdomain": subdomain,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
        "port": port,
        "missing_scheme": missing_scheme,
        "is_shortener": site_private in KNOWN_SHORTENERS,
    }


def normalized_url(raw: str, row: pd.Series | dict) -> str:
    host = row.get("hostname_ascii")
    if not isinstance(host, str) or not host:
        return "UNPARSEABLE:" + str(raw).strip()
    try:
        parts = urlsplit(str(raw).strip())
        if not parts.scheme:
            parts = urlsplit("//" + str(raw).strip())
        scheme = parts.scheme.lower()
        port = row.get("port")
        is_ip = bool(row.get("is_ip"))
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"[{host}]:{port}" if is_ip and ":" in host else f"{host}:{port}"
        else:
            netloc = f"[{host}]" if is_ip and ":" in host else host
        path = parts.path if parts.path else "/"
        return urlunsplit(SplitResult(scheme, netloc, path, parts.query, ""))
    except Exception:
        return "UNPARSEABLE:" + str(raw).strip()
