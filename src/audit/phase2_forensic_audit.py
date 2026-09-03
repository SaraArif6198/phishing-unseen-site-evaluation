from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

import numpy as np
import pandas as pd
import idna
import tldextract


ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "data_phase2/raw/legitphish/url_features_extracted1.csv"
PSL = ROOT / "data_phase2/psl/public_suffix_list_2026-08-17.dat"
OUT = ROOT / "data_phase2/outputs/legitphish"
OUT.mkdir(parents=True, exist_ok=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


extract_icann = tldextract.TLDExtract(
    suffix_list_urls=(PSL.resolve().as_uri(),),
    cache_dir=None,
    fallback_to_snapshot=False,
    include_psl_private_domains=False,
)
extract_private = tldextract.TLDExtract(
    suffix_list_urls=(PSL.resolve().as_uri(),),
    cache_dir=None,
    fallback_to_snapshot=False,
    include_psl_private_domains=True,
)


def parse_url(raw: object) -> dict:
    if not isinstance(raw, str) or not raw.strip():
        return {"parse_status": "MISSING_URL"}
    u = raw.strip()
    try:
        first = urlsplit(u)
        missing_scheme = not first.scheme
        parts = urlsplit("//" + u) if missing_scheme else first
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

    is_ip = False
    is_private_ip = False
    try:
        ip = ipaddress.ip_address(host_ascii.strip("[]"))
        is_ip = True
        is_private_ip = bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        host_ascii = ip.compressed
    except ValueError:
        pass

    unsupported = bool(scheme and scheme not in {"http", "https"})
    if is_ip:
        site_icann = site_private = host_ascii
        suffix_icann = suffix_private = ""
        subdomain = ""
        is_private_suffix = False
    else:
        ei = extract_icann(host_ascii)
        ep = extract_private(host_ascii)
        site_icann = ei.top_domain_under_public_suffix or ""
        site_private = ep.top_domain_under_public_suffix or ""
        suffix_icann = ei.suffix or ""
        suffix_private = ep.suffix or ""
        subdomain = ep.subdomain or ""
        is_private_suffix = bool(getattr(ep, "is_private", False))

    local_host = is_private_ip or host_ascii == "localhost" or (not is_ip and "." not in host_ascii)
    if unsupported:
        status = "UNSUPPORTED_SCHEME"
    elif local_host:
        status = "LOCAL_OR_PRIVATE_HOST"
    elif missing_scheme:
        status = "MISSING_SCHEME_RECOVERABLE"
    elif is_ip:
        status = "VALID_IP_HOST_URL"
    elif not site_private:
        status = "MALFORMED_OR_NONPUBLIC_DNS_HOST"
    elif is_private_suffix:
        status = "VALID_PRIVATE_SUFFIX_URL"
    else:
        status = "VALID_PUBLIC_DNS_URL"

    try:
        port = parts.port
    except ValueError:
        port = None
        status = "MALFORMED_PORT"

    return {
        "parse_status": status,
        "scheme": scheme,
        "hostname_raw": host_raw,
        "hostname_ascii": host_ascii,
        "is_ip": is_ip,
        "is_private_ip": is_private_ip,
        "public_suffix_icann": suffix_icann,
        "public_suffix_private": suffix_private,
        "site_key_icann": site_icann,
        "site_key_private": site_private,
        "subdomain": subdomain,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
        "port": port,
        "is_private_suffix": is_private_suffix,
        "missing_scheme": missing_scheme,
    }


def conservative_norm(raw: str, row: pd.Series) -> str:
    if not row.get("hostname_ascii"):
        return "UNPARSEABLE:" + raw.strip()
    try:
        parts = urlsplit(raw.strip())
        if not parts.scheme:
            parts = urlsplit("//" + raw.strip())
        scheme = parts.scheme.lower()
        host = row["hostname_ascii"]
        port = row.get("port")
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"[{host}]:{port}" if row.get("is_ip") and ":" in host else f"{host}:{port}"
        else:
            netloc = f"[{host}]" if row.get("is_ip") and ":" in host else host
        path = parts.path if parts.path else "/"
        return urlunsplit(SplitResult(scheme, netloc, path, parts.query, ""))
    except Exception:
        return "UNPARSEABLE:" + raw.strip()


def gini(values: np.ndarray) -> float:
    values = np.asarray(values, dtype=float)
    if len(values) == 0 or values.sum() == 0:
        return float("nan")
    values = np.sort(values)
    n = len(values)
    return float((2 * np.sum(np.arange(1, n + 1) * values) / (n * values.sum())) - (n + 1) / n)


def sites_to_cover(values: np.ndarray, share: float) -> int:
    values = np.sort(np.asarray(values, dtype=int))[::-1]
    return int(np.searchsorted(np.cumsum(values), values.sum() * share, side="left") + 1)


def multiplicity_table(frame: pd.DataFrame, key: str) -> list[dict]:
    rows = []
    for label, name in [(0.0, "phishing"), (1.0, "benign")]:
        z = frame[frame.ClassLabel == label]
        counts = z.groupby(key, dropna=False).size()
        rows.append({
            "class": name,
            "urls": int(len(z)),
            "hostnames": int(z.hostname_ascii.nunique()),
            "site_keys": int(z[key].nunique()),
            "mean_urls_per_site": float(counts.mean()),
            "median_urls_per_site": float(counts.median()),
            "p75": float(counts.quantile(.75)),
            "p90": float(counts.quantile(.90)),
            "p95": float(counts.quantile(.95)),
            "max": int(counts.max()),
            "sites_eq_1": int((counts == 1).sum()),
            "sites_ge_2": int((counts >= 2).sum()),
            "sites_ge_5": int((counts >= 5).sum()),
            "sites_ge_10": int((counts >= 10).sum()),
            "sites_ge_50": int((counts >= 50).sum()),
            "sites_ge_100": int((counts >= 100).sum()),
            "top1_share": float(counts.nlargest(1).sum() / counts.sum()),
            "top10_share": float(counts.nlargest(10).sum() / counts.sum()),
            "top100_share": float(counts.nlargest(100).sum() / counts.sum()),
            "gini": gini(counts.to_numpy()),
            "sites_cover_50pct": sites_to_cover(counts.to_numpy(), .5),
            "sites_cover_90pct": sites_to_cover(counts.to_numpy(), .9),
        })
    return rows


def random_split_leakage(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []
    labels = frame.ClassLabel.to_numpy()
    for seed in [13, 42, 73, 101, 2026]:
        rng = np.random.default_rng(seed)
        assignments = np.empty(len(frame), dtype=object)
        for label in [0.0, 1.0]:
            idx = np.flatnonzero(labels == label)
            rng.shuffle(idx)
            ntrain = int(round(.70 * len(idx)))
            nval = int(round(.15 * len(idx)))
            assignments[idx[:ntrain]] = "train"
            assignments[idx[ntrain:ntrain + nval]] = "validation"
            assignments[idx[ntrain + nval:]] = "test"
        train = frame[assignments == "train"]
        test = frame[assignments == "test"]
        train_hosts = set(train.hostname_ascii)
        train_sites = set(train.site_key_private)
        for label, name in [(None, "all"), (0.0, "phishing"), (1.0, "benign")]:
            z = test if label is None else test[test.ClassLabel == label]
            rows.append({
                "seed": seed,
                "class": name,
                "test_urls": len(z),
                "shared_hostnames": len(set(z.hostname_ascii) & train_hosts),
                "shared_site_keys": len(set(z.site_key_private) & train_sites),
                "test_urls_seen_hostname_pct": 100 * z.hostname_ascii.isin(train_hosts).mean(),
                "test_urls_seen_site_pct": 100 * z.site_key_private.isin(train_sites).mean(),
            })
    return pd.DataFrame(rows)


def structure_table(frame: pd.DataFrame) -> pd.DataFrame:
    x = frame.copy()
    x["root_only"] = (x.path.fillna("").isin(["", "/"])) & x["query"].fillna("").eq("")
    x["path_present"] = ~x.path.fillna("").isin(["", "/"])
    x["query_present"] = x["query"].fillna("").ne("")
    x["fragment_present"] = x["fragment"].fillna("").ne("")
    x["https"] = x.scheme.eq("https")
    x["www"] = x.hostname_ascii.fillna("").str.startswith("www.")
    x["punycode"] = x.hostname_ascii.fillna("").str.contains("xn--", regex=False)
    x["percent_encoded"] = x.URL.str.contains("%", regex=False)
    x["hostname_length"] = x.hostname_ascii.fillna("").str.len()
    x["path_length_parsed"] = x.path.fillna("").str.len()
    x["url_length_observed"] = x.URL.str.len()
    metrics = ["root_only", "path_present", "query_present", "fragment_present", "https", "www", "is_ip", "punycode", "percent_encoded", "url_length_observed", "hostname_length", "path_length_parsed"]
    out = []
    for metric in metrics:
        a = x.loc[x.ClassLabel == 0.0, metric].mean()
        b = x.loc[x.ClassLabel == 1.0, metric].mean()
        out.append({"property": metric, "phishing": a, "benign": b, "absolute_difference": abs(a-b)})
    return pd.DataFrame(out)


def template_key(row: pd.Series) -> str:
    host = row.get("hostname_ascii")
    site = row.get("site_key_private")
    host = host if isinstance(host, str) else ""
    site = site if isinstance(site, str) else ""
    sub = host[:-len(site)].rstrip(".") if site and host.endswith(site) else host
    value = f"{sub}/" + (row.get("path") or "") + "?" + (row.get("query") or "")
    value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "<EMAIL>", value)
    value = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<HEX>", value)
    value = re.sub(r"\b\d{6,}\b", "<NUM>", value)
    value = re.sub(r"[A-Za-z0-9_-]{24,}", "<TOKEN>", value)
    return value.lower()


def main() -> None:
    df = pd.read_csv(INPUT)
    df.insert(0, "row_id", np.arange(len(df), dtype=np.int64))
    parsed = pd.DataFrame([parse_url(u) for u in df.URL])
    x = pd.concat([df, parsed], axis=1)
    x["norm_url"] = [conservative_norm(u, row) for u, (_, row) in zip(x.URL, x.iterrows())]
    x["template_key"] = x.apply(template_key, axis=1)
    x.to_parquet(OUT / "parsed_urls.parquet", index=False)

    labelled = x[x.ClassLabel.isin([0.0, 1.0])].copy()
    valid_group = labelled.site_key_private.fillna("").ne("")
    analysis = labelled[valid_group].copy()

    exact_counts = labelled.groupby("URL", dropna=False).agg(rows=("row_id", "size"), labels=("ClassLabel", "nunique"), sites=("site_key_private", "nunique"))
    norm_counts = labelled.groupby("norm_url", dropna=False).agg(rows=("row_id", "size"), labels=("ClassLabel", "nunique"), sites=("site_key_private", "nunique"))
    exact_summary = {
        "total_labelled_rows": len(labelled), "unique_raw_urls": int(labelled.URL.nunique()),
        "duplicate_rows_beyond_first": int(len(labelled) - labelled.URL.nunique()),
        "duplicate_rate_pct": float(100 * (len(labelled) - labelled.URL.nunique()) / len(labelled)),
        "cross_label_exact_conflict_keys": int((exact_counts.labels > 1).sum()),
    }
    norm_summary = {
        "unique_raw_urls": int(labelled.URL.nunique()), "unique_norm_urls": int(labelled.norm_url.nunique()),
        "normalized_duplicate_rows_beyond_first": int(len(labelled) - labelled.norm_url.nunique()),
        "normalized_duplicate_rate_pct": float(100 * (len(labelled) - labelled.norm_url.nunique()) / len(labelled)),
        "cross_label_norm_conflict_keys": int((norm_counts.labels > 1).sum()),
    }

    validity = x.groupby(["parse_status", "ClassLabel"], dropna=False).size().reset_index(name="rows")
    validity.to_csv(OUT / "url_validity_profile.csv", index=False)
    pd.DataFrame(multiplicity_table(analysis, "site_key_private")).to_csv(OUT / "site_multiplicity_private.csv", index=False)
    pd.DataFrame(multiplicity_table(analysis[analysis.site_key_icann.fillna("").ne("")], "site_key_icann")).to_csv(OUT / "site_multiplicity_icann.csv", index=False)
    random_split_leakage(analysis).to_csv(OUT / "random_split_domain_leakage.csv", index=False)
    structure_table(analysis).to_csv(OUT / "class_structural_disparity.csv", index=False)

    site_labels = analysis.groupby("site_key_private").ClassLabel.nunique()
    host_labels = analysis.groupby("hostname_ascii").ClassLabel.nunique()
    private_changed = analysis.site_key_icann.ne(analysis.site_key_private)
    private_summary = {
        "unique_site_icann": int(analysis.site_key_icann.nunique()),
        "unique_site_private": int(analysis.site_key_private.nunique()),
        "urls_grouping_changed": int(private_changed.sum()),
        "urls_grouping_changed_pct": float(100 * private_changed.mean()),
        "private_suffix_rows": int(analysis.is_private_suffix.sum()),
        "mixed_label_private_sites": int((site_labels > 1).sum()),
        "mixed_label_hostnames": int((host_labels > 1).sum()),
    }

    tld_table = pd.crosstab(analysis.public_suffix_private, analysis.ClassLabel)
    tld_table.columns = ["phishing" if c == 0.0 else "benign" for c in tld_table.columns]
    tld_table["total"] = tld_table.sum(axis=1)
    tld_table["phishing_probability"] = tld_table.get("phishing", 0) / tld_table.total
    tld_table.sort_values("total", ascending=False).to_csv(OUT / "tld_by_class.csv")
    observed = pd.crosstab(analysis.public_suffix_private, analysis.ClassLabel).to_numpy()
    expected = observed.sum(axis=1, keepdims=True) @ observed.sum(axis=0, keepdims=True) / observed.sum()
    chi2 = np.nansum((observed - expected) ** 2 / np.where(expected == 0, np.nan, expected))
    cramers_v = math.sqrt(chi2 / (observed.sum() * min(observed.shape[0] - 1, observed.shape[1] - 1)))

    template_sites = analysis.groupby("template_key").site_key_private.nunique()
    cross_site_templates = set(template_sites[template_sites > 1].index)
    template_summary = {
        "unique_template_keys": int(analysis.template_key.nunique()),
        "template_keys_shared_across_sites": int(len(cross_site_templates)),
        "rows_in_cross_site_templates": int(analysis.template_key.isin(cross_site_templates).sum()),
        "rows_in_cross_site_templates_pct": float(100 * analysis.template_key.isin(cross_site_templates).mean()),
    }

    top_private = analysis.groupby(["site_key_private", "ClassLabel"]).size().reset_index(name="rows")
    top_private["class"] = top_private.ClassLabel.map({0.0: "phishing", 1.0: "benign"})
    top_private.sort_values("rows", ascending=False).drop(columns="ClassLabel").head(50).to_csv(OUT / "top_sites_redacted.csv", index=False)

    summary = {
        "inventory": {
            "file": INPUT.name, "size_bytes": INPUT.stat().st_size, "sha256": sha256(INPUT),
            "rows": len(df), "columns": list(df.columns), "missing_label_rows": int(df.ClassLabel.isna().sum()),
            "label_counts": {str(k): int(v) for k, v in df.ClassLabel.value_counts(dropna=False).items()},
            "psl_file": PSL.name, "psl_sha256": sha256(PSL),
            "tldextract_version": tldextract.__version__, "idna_version": idna.__version__,
        },
        "exact_duplicates": exact_summary,
        "normalized_duplicates": norm_summary,
        "grouping": private_summary,
        "tld_cramers_v": float(cramers_v),
        "template_similarity": template_summary,
        "analysis_rows": len(analysis),
        "unique_hostnames": int(analysis.hostname_ascii.nunique()),
        "unique_site_keys_private": int(analysis.site_key_private.nunique()),
        "unique_site_keys_icann": int(analysis.site_key_icann.nunique()),
        "ip_rows": int(analysis.is_ip.sum()),
        "ip_keys": int(analysis.loc[analysis.is_ip, "site_key_private"].nunique()),
    }
    (OUT / "audit_summary.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
