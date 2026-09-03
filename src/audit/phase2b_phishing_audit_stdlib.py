from __future__ import annotations

import bz2
import csv
import hashlib
import ipaddress
import json
import random
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "data_phase2b/raw/phishing/online-valid_2026-08-17.csv.bz2"
PSL = ROOT / "data_phase2/psl/public_suffix_list_2026-08-17.dat"
OUT = ROOT / "data_phase2b/audit/phishing_stdlib_audit.json"
SEEDS = [13, 42, 73, 101, 2026]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_psl() -> tuple[set[str], set[str], set[str], set[str], set[str], set[str]]:
    icann, private = set(), set()
    current = icann
    for raw in PSL.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "// ===BEGIN PRIVATE DOMAINS===":
            current = private
            continue
        if not line or line.startswith("//"):
            continue
        current.add(line.lower())

    def divide(rules: set[str]) -> tuple[set[str], set[str], set[str]]:
        exact, wildcard, exception = set(), set(), set()
        for rule in rules:
            if rule.startswith("!…"):
                exception.add(rule[2:])
            elif rule.startswith("!"):
                exception.add(rule[1:])
            elif rule.startswith("*."):
                wildcard.add(rule[2:])
            else:
                exact.add(rule)
        return exact, wildcard, exception

    return (*divide(icann), *divide(icann | private))


ICANN_EXACT, ICANN_WILD, ICANN_EXC, ALL_EXACT, ALL_WILD, ALL_EXC = load_psl()


def registrable(host: str, private: bool) -> tuple[str, str, bool]:
    exact, wildcard, exception = ((ALL_EXACT, ALL_WILD, ALL_EXC) if private
                                  else (ICANN_EXACT, ICANN_WILD, ICANN_EXC))
    labels = host.split(".")
    exception_match = None
    best = 1
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in exception:
            exception_match = cand
            break
        if cand in exact:
            best = max(best, len(labels) - i)
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wildcard:
            best = max(best, len(labels) - i)
    if exception_match:
        suffix_len = len(exception_match.split(".")) - 1
    else:
        suffix_len = best
    suffix = ".".join(labels[-suffix_len:])
    if len(labels) <= suffix_len:
        return "", suffix, False
    key = ".".join(labels[-(suffix_len + 1):])
    is_private = private and suffix not in ICANN_EXACT and suffix not in ICANN_WILD
    return key, suffix, is_private


def parse(raw: str) -> dict:
    try:
        parts = urlsplit(raw.strip())
        if not parts.scheme:
            parts = urlsplit("//" + raw.strip())
            missing_scheme = True
        else:
            missing_scheme = False
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            return {"status": "MISSING_HOST"}
        host = host.encode("idna").decode("ascii").lower()
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                status = "LOCAL_OR_PRIVATE_HOST"
            elif parts.scheme.lower() not in {"http", "https"}:
                status = "UNSUPPORTED_SCHEME"
            elif missing_scheme:
                status = "MISSING_SCHEME_RECOVERABLE"
            else:
                status = "VALID_IP_HOST_URL"
            site_i = site_p = ip.compressed
            suffix_i = suffix_p = ""
            is_ip = True
            is_private_suffix = False
        except ValueError:
            site_i, suffix_i, _ = registrable(host, False)
            site_p, suffix_p, is_private_suffix = registrable(host, True)
            if parts.scheme.lower() not in {"http", "https"}:
                status = "UNSUPPORTED_SCHEME"
            elif missing_scheme:
                status = "MISSING_SCHEME_RECOVERABLE"
            elif not site_p:
                status = "MALFORMED_OR_NONPUBLIC_DNS_HOST"
            elif is_private_suffix:
                status = "VALID_PRIVATE_SUFFIX_URL"
            else:
                status = "VALID_PUBLIC_DNS_URL"
            is_ip = False
        scheme = parts.scheme.lower()
        port = parts.port
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = host if not port or default else f"{host}:{port}"
        norm = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
        return {
            "status": status, "host": host, "is_ip": is_ip,
            "site_icann": site_i, "site_private": site_p,
            "suffix_icann": suffix_i, "suffix_private": suffix_p,
            "is_private_suffix": is_private_suffix, "scheme": scheme,
            "path": parts.path, "query": parts.query, "normalized": norm,
            "root_only": (parts.path in {"", "/"} and not parts.query),
            "www": host.startswith("www."),
            "encoded": bool(re.search(r"%[0-9A-Fa-f]{2}", raw)),
            "punycode": "xn--" in host,
            "url_length": len(raw), "host_length": len(host),
            "path_length": len(parts.path),
        }
    except ValueError:
        return {"status": "MALFORMED_PORT"}
    except Exception:
        return {"status": "MALFORMED_URL"}


def quantile(values: list[int], q: float) -> float:
    if not values:
        return float("nan")
    x = sorted(values)
    pos = (len(x) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(x) - 1)
    return x[lo] + (x[hi] - x[lo]) * (pos - lo)


def multiplicity(records: list[dict]) -> dict:
    counts = Counter(r["site_private"] for r in records)
    vals = list(counts.values())
    return {
        "urls": len(records), "hostnames": len({r["host"] for r in records}),
        "site_keys": len(counts), "mean_urls_per_site": sum(vals) / len(vals),
        "median": statistics.median(vals), "p75": quantile(vals, .75),
        "p90": quantile(vals, .90), "p95": quantile(vals, .95),
        "max": max(vals), "sites_eq1": sum(v == 1 for v in vals),
        "sites_ge2": sum(v >= 2 for v in vals), "sites_ge5": sum(v >= 5 for v in vals),
        "sites_ge10": sum(v >= 10 for v in vals), "sites_ge50": sum(v >= 50 for v in vals),
    }


def cap(records: list[dict], n: int) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in records:
        grouped[row["site_private"]].append(row)
    out = []
    for site in sorted(grouped):
        out.extend(sorted(grouped[site], key=lambda r: hashlib.sha256(r["normalized"].encode()).hexdigest())[:n])
    return out


def exposure(records: list[dict]) -> list[dict]:
    out = []
    for seed in SEEDS:
        order = list(range(len(records)))
        random.Random(seed).shuffle(order)
        train_n = int(round(.70 * len(order)))
        test_start = train_n + int(round(.15 * len(order)))
        train = [records[i] for i in order[:train_n]]
        test = [records[i] for i in order[test_start:]]
        train_sites = {r["site_private"] for r in train}
        train_hosts = {r["host"] for r in train}
        out.append({
            "seed": seed, "test_rows": len(test),
            "hostname_seen_rate": sum(r["host"] in train_hosts for r in test) / len(test),
            "site_seen_rate": sum(r["site_private"] in train_sites for r in test) / len(test),
        })
    return out


def main() -> None:
    rows, parsed = [], []
    with bz2.open(SOURCE, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append(row)
            item = parse(row.get("url", ""))
            item.update({"raw_url": row.get("url", ""), "phish_id": row.get("phish_id", "")})
            parsed.append(item)

    status = Counter(r["status"] for r in parsed)
    raw_counts = Counter(r["raw_url"] for r in parsed)
    norm_counts = Counter(r.get("normalized") for r in parsed if r.get("normalized"))
    dns = [r for r in parsed if r["status"] in {"VALID_PUBLIC_DNS_URL", "VALID_PRIVATE_SUFFIX_URL"}]
    unique_dns = {}
    for r in sorted(dns, key=lambda x: (x["site_private"], hashlib.sha256(x["normalized"].encode()).hexdigest())):
        unique_dns.setdefault(r["normalized"], r)
    eligible = list(unique_dns.values())
    cap5 = cap(eligible, 5)
    timestamps_1 = [datetime.fromisoformat(r["submission_time"]) for r in rows if r.get("submission_time")]
    timestamps_2 = [datetime.fromisoformat(r["verification_time"]) for r in rows if r.get("verification_time")]
    targets = Counter((r.get("target") or "Other").strip() for r in rows)

    result = {
        "source_file": str(SOURCE.relative_to(ROOT)), "source_sha256": sha256(SOURCE),
        "psl_sha256": sha256(PSL), "rows": len(rows), "columns": list(rows[0]),
        "verified_values": dict(Counter(r.get("verified") for r in rows)),
        "online_values": dict(Counter(r.get("online") for r in rows)),
        "parse_status": dict(status), "unique_raw_urls": len(raw_counts),
        "exact_duplicate_rows_beyond_first": sum(v - 1 for v in raw_counts.values()),
        "unique_normalized_urls": len(norm_counts),
        "normalized_duplicate_rows_beyond_first": sum(v - 1 for v in norm_counts.values()),
        "dns_eligible_unique_normalized": len(eligible),
        "dns_uncapped_multiplicity": multiplicity(eligible),
        "dns_cap5_multiplicity": multiplicity(cap5),
        "dns_cap5_random_split_exposure": exposure(cap5),
        "timestamp_ranges": {
            "submission_time_min": min(timestamps_1).isoformat(), "submission_time_max": max(timestamps_1).isoformat(),
            "verification_time_min": min(timestamps_2).isoformat(), "verification_time_max": max(timestamps_2).isoformat(),
        },
        "structural_dns_uncapped": {
            "root_only_rate": sum(r["root_only"] for r in eligible) / len(eligible),
            "https_rate": sum(r["scheme"] == "https" for r in eligible) / len(eligible),
            "www_rate": sum(r["www"] for r in eligible) / len(eligible),
            "query_rate": sum(bool(r["query"]) for r in eligible) / len(eligible),
            "punycode_rate": sum(r["punycode"] for r in eligible) / len(eligible),
            "encoded_rate": sum(r["encoded"] for r in eligible) / len(eligible),
            "url_length_mean": statistics.mean(r["url_length"] for r in eligible),
            "url_length_median": statistics.median(r["url_length"] for r in eligible),
        },
        "top_targets": targets.most_common(20),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
