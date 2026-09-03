"""
Phase 3 URL Feature Engineering Module.

Provides deterministic, non-predictive feature extraction for the 22 frozen URL-only features
specified in data/interim/phase2c/step23_phase3_execution_bundle/engineered_feature_contract.json.

Strict Rules:
- Consumes raw_url and parsed URL fields only.
- NO statistical fitting, scaling, or model parameter estimation.
- NO access to target labels, candidate IDs, crawl IDs, Tranco ranks, site keys, or future statistics.
- 100% deterministic output.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Dict

PERCENT_ENCODED_REGEX = re.compile(r'%[0-9A-Fa-f]{2}')
SPECIAL_CHARS = set('@?=&#~%')

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "path_depth",
    "subdomain_depth",
    "has_query",
    "has_port",
    "is_root_path",
    "digit_count",
    "digit_ratio",
    "hyphen_count",
    "dot_count",
    "special_char_count",
    "percent_encoded_count",
    "char_entropy",
    "is_ip",
    "is_private_suffix",
    "has_www",
    "is_https",
    "is_missing_scheme",
    "has_punycode",
]

def calculate_shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def extract_22_url_features(record: Dict[str, Any]) -> Dict[str, Any]:
    raw_url = str(record.get("raw_url") or "").strip()
    
    # Extract parsed properties (falling back to parser or parsing inline if needed)
    hostname_raw = str(record.get("hostname_raw") or record.get("hostname") or "").strip().lower()
    hostname_ascii = str(record.get("hostname_ascii") or record.get("hostname") or "").strip().lower()
    path = str(record.get("path") if record.get("path") is not None else "").strip()
    query = str(record.get("query") if record.get("query") is not None else "").strip()
    subdomain = str(record.get("subdomain") or "").strip()
    scheme = str(record.get("scheme") or "").strip().lower()
    
    # Infer scheme from raw_url if missing in record dict
    if not scheme and "://" in raw_url:
        scheme = raw_url.split("://", 1)[0].lower()
        
    missing_scheme = bool(record.get("missing_scheme", False))
    if not missing_scheme and "://" not in raw_url and raw_url:
        missing_scheme = True
        
    is_ip = bool(record.get("is_ip", False))
    is_private_suffix = bool(record.get("is_private_suffix", False))
    port = record.get("port")
    
    url_len = len(raw_url)
    host_len = len(hostname_ascii)
    path_len = len(path)
    query_len = len(query)
    
    path_depth = path.count('/')
    subdomain_depth = subdomain.count('.') if subdomain else 0
    has_query = 1 if query else 0
    has_port = 1 if (port is not None and port not in (80, 443)) else 0
    is_root_path = 1 if (path in ('', '/') and not query) else 0
    
    combined_str = hostname_ascii + path + query
    digit_count = sum(1 for c in combined_str if c.isdigit())
    digit_ratio = float(digit_count / url_len) if url_len > 0 else 0.0
    
    hyphen_count = hostname_ascii.count('-')
    dot_count = hostname_ascii.count('.')
    special_char_count = sum(1 for c in raw_url if c in SPECIAL_CHARS)
    percent_encoded_count = len(PERCENT_ENCODED_REGEX.findall(raw_url))
    
    char_entropy = calculate_shannon_entropy(hostname_ascii)
    
    is_ip_val = 1 if is_ip else 0
    is_private_suffix_val = 1 if is_private_suffix else 0
    
    first_subdomain_label = subdomain.split('.')[0] if subdomain else ""
    has_www_val = 1 if (first_subdomain_label == "www" or hostname_ascii.startswith("www.")) else 0
    
    is_https_val = 1 if scheme == "https" else 0
    is_missing_scheme_val = 1 if missing_scheme else 0
    has_punycode_val = 1 if "xn--" in hostname_raw else 0
    
    return {
        "url_length": int(url_len),
        "hostname_length": int(host_len),
        "path_length": int(path_len),
        "query_length": int(query_len),
        "path_depth": int(path_depth),
        "subdomain_depth": int(subdomain_depth),
        "has_query": int(has_query),
        "has_port": int(has_port),
        "is_root_path": int(is_root_path),
        "digit_count": int(digit_count),
        "digit_ratio": float(digit_ratio),
        "hyphen_count": int(hyphen_count),
        "dot_count": int(dot_count),
        "special_char_count": int(special_char_count),
        "percent_encoded_count": int(percent_encoded_count),
        "char_entropy": float(char_entropy),
        "is_ip": int(is_ip_val),
        "is_private_suffix": int(is_private_suffix_val),
        "has_www": int(has_www_val),
        "is_https": int(is_https_val),
        "is_missing_scheme": int(is_missing_scheme_val),
        "has_punycode": int(has_punycode_val),
    }
