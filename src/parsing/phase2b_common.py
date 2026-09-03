from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna
import pandas as pd
import tldextract


ROOT = Path(__file__).resolve().parent
PSL = ROOT / "data_phase2/psl/public_suffix_list_2026-08-17.dat"

EXTRACT_ICANN = tldextract.TLDExtract(
    suffix_list_urls=(PSL.resolve().as_uri(),), cache_dir=None,
    fallback_to_snapshot=False, include_psl_private_domains=False,
)
EXTRACT_PRIVATE = tldextract.TLDExtract(
    suffix_list_urls=(PSL.resolve().as_uri(),), cache_dir=None,
    fallback_to_snapshot=False, include_psl_private_domains=True,
)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
        return {"parse_status": "MISSING_HOST", "scheme": scheme,
                "path": parts.path, "query": parts.query, "fragment": parts.fragment}
    host_raw = host_raw.rstrip(".").lower()
    try:
        host_ascii = idna.encode(host_raw, uts46=True, std3_rules=True).decode("ascii").lower()
    except Exception:
        return {"parse_status": "MALFORMED_IDN_HOST", "scheme": scheme,
                "hostname_raw": host_raw, "path": parts.path,
                "query": parts.query, "fragment": parts.fragment}
    is_ip = False
    private_ip = False
    try:
        ip = ipaddress.ip_address(host_ascii.strip("[]"))
        is_ip = True
        private_ip = bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        host_ascii = ip.compressed
    except ValueError:
        pass
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
        "parse_status": status, "scheme": scheme, "hostname_raw": host_raw,
        "hostname_ascii": host_ascii, "is_ip": is_ip, "is_private_ip": private_ip,
        "public_suffix_icann": suffix_icann, "public_suffix_private": suffix_private,
        "site_key_icann": site_icann, "site_key_private": site_private,
        "is_private_suffix": private_suffix, "subdomain": subdomain,
        "path": parts.path, "query": parts.query, "fragment": parts.fragment,
        "port": port, "missing_scheme": missing_scheme,
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


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
