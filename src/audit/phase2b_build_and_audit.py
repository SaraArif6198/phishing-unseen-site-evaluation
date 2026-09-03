from __future__ import annotations

import bz2
import json
import math
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from phase2b_common import ROOT, hash_text, normalized_url, parse_url, sha256


BASE = ROOT / "data_phase2b"
RAW_P = BASE / "raw/phishing/online-valid_2026-08-17.csv.bz2"
RAW_B = BASE / "raw/benign/commoncrawl_CC-MAIN-2026-30_candidates.parquet"
PROC = BASE / "processed"
AUDIT = BASE / "audit"
MAN = BASE / "manifests"
SEEDS = [13, 42, 73, 101, 2026]
VALID_DNS = {"VALID_PUBLIC_DNS_URL", "VALID_PRIVATE_SUFFIX_URL"}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")


def read_sources() -> tuple[pd.DataFrame, pd.DataFrame]:
    with bz2.open(RAW_P, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        p = pd.read_csv(fh)
    p = p.rename(columns={"url": "raw_url", "phish_id": "source_record_id"})
    p["record_id"] = "pt:" + p["source_record_id"].astype(str)
    p["label"] = 1
    p["source_name"] = "PhishTank online-valid"
    p["source_snapshot"] = RAW_P.name
    p["source_timestamp_1"] = p["submission_time"]
    p["source_timestamp_2"] = p["verification_time"]
    p["source_semantics"] = "submission_time; community verification_time"
    p["acquisition_date"] = "2026-08-17"
    p["source_license"] = "PhishTank/Cisco terms; raw redistribution not established"
    p["source_url_or_reference"] = "https://www.phishtank.net/developer_info.php"
    p["target_brand"] = p["target"]
    p["crawl_id"] = pd.NA
    p["crawl_timestamp"] = pd.NA
    p["tranco_list_id"] = pd.NA
    p["tranco_rank"] = pd.NA

    b = pd.read_parquet(RAW_B)
    b["record_id"] = [f"cc:{i:07d}" for i in range(len(b))]
    b["source_record_id"] = b["record_id"].astype(str)
    b["label"] = 0
    b["source_name"] = "Common Crawl URL Index via Tranco frame"
    b["source_snapshot"] = b["crawl_id"]
    b["source_timestamp_1"] = b["crawl_timestamp"]
    b["source_timestamp_2"] = pd.NA
    b["source_semantics"] = "Common Crawl index capture timestamp"
    b["acquisition_date"] = "2026-08-17"
    b["source_license"] = "Common Crawl Terms of Use; underlying URL rights may vary"
    b["source_url_or_reference"] = "https://index.commoncrawl.org/"
    b["target_brand"] = pd.NA
    b["tranco_list_id"] = "26J39"
    for col in ["submission_time", "verification_time", "verified", "online", "target", "phish_detail_url"]:
        b[col] = pd.NA
    common = [
        "record_id", "raw_url", "label", "source_name", "source_record_id",
        "source_snapshot", "source_timestamp_1", "source_timestamp_2",
        "source_semantics", "acquisition_date", "source_license",
        "source_url_or_reference", "crawl_id", "crawl_timestamp", "tranco_list_id",
        "tranco_rank", "target_brand", "submission_time", "verification_time",
        "verified", "online", "target", "phish_detail_url",
    ]
    return p[common].copy(), b[common].copy()


def parse_frame(raw: pd.DataFrame) -> pd.DataFrame:
    parsed = pd.DataFrame([parse_url(v) for v in raw["raw_url"]])
    out = pd.concat([raw.reset_index(drop=True), parsed], axis=1)
    out["normalized_url"] = [normalized_url(u, r) for u, (_, r) in zip(out.raw_url, out.iterrows())]
    out["raw_url_hash"] = out.raw_url.astype(str).map(hash_text)
    out["normalized_url_hash"] = out.normalized_url.astype(str).map(hash_text)
    out["url_length"] = out.raw_url.astype(str).str.len()
    out["hostname_length"] = out.hostname_ascii.fillna("").astype(str).str.len()
    out["path_length"] = out.path.fillna("").astype(str).str.len()
    out["query_present"] = out.query.fillna("").astype(str).ne("")
    out["root_only"] = out.path.fillna("").isin(["", "/"]) & ~out.query_present
    out["www"] = out.hostname_ascii.fillna("").astype(str).str.startswith("www.")
    out["encoded"] = out.raw_url.astype(str).str.contains(r"%[0-9A-Fa-f]{2}", regex=True)
    out["punycode"] = out.hostname_ascii.fillna("").astype(str).str.contains("xn--", regex=False)
    out["subdomain_depth"] = out.subdomain.fillna("").astype(str).map(lambda x: 0 if not x else x.count(".") + 1)
    return out


def validity(parsed: pd.DataFrame) -> None:
    tab = parsed.groupby(["label", "parse_status"], dropna=False).size().rename("rows").reset_index()
    tab.to_csv(AUDIT / "url_validity_by_class.csv", index=False)


def duplicate_audit(parsed: pd.DataFrame) -> None:
    exact = parsed.groupby("raw_url_hash").agg(rows=("record_id", "size"), labels=("label", "nunique"),
                                                    sources=("source_name", "nunique")).reset_index()
    exact[exact.rows > 1].to_csv(AUDIT / "exact_duplicates.csv", index=False)
    norm = parsed.groupby("normalized_url_hash").agg(rows=("record_id", "size"), labels=("label", "nunique"),
                                                           sources=("source_name", "nunique")).reset_index()
    norm[norm.rows > 1].to_csv(AUDIT / "normalized_duplicates.csv", index=False)
    parsed[parsed.raw_url_hash.isin(exact.loc[exact.labels > 1, "raw_url_hash"])][
        ["record_id", "label", "raw_url_hash", "normalized_url_hash", "site_key_private", "source_name"]
    ].to_csv(AUDIT / "cross_label_conflicts.csv", index=False)
    mixed = parsed[parsed.site_key_private.fillna("").ne("")].groupby("site_key_private").agg(
        rows=("record_id", "size"), labels=("label", "nunique"), phishing=("label", "sum"),
        sources=("source_name", "nunique")
    ).reset_index()
    mixed[mixed.labels > 1].assign(site_key_private=lambda x: x.site_key_private.map(hash_text)).to_csv(
        AUDIT / "mixed_label_sites_redacted.csv", index=False)


def multiplicity_table(df: pd.DataFrame, key: str, suffix: str) -> None:
    grouped = df.groupby(["label", key]).size().rename("urls").reset_index()
    grouped.assign(**{key: grouped[key].astype(str).map(hash_text)}).to_csv(AUDIT / f"urls_per_{suffix}_redacted.csv", index=False)
    rows = []
    for label, g in grouped.groupby("label"):
        x = g.urls
        rows.append({
            "label": int(label), "urls": int(x.sum()), "groups": int(len(x)), "mean": x.mean(),
            "median": x.median(), "p75": x.quantile(.75), "p90": x.quantile(.90),
            "p95": x.quantile(.95), "max": int(x.max()), "groups_eq1": int((x == 1).sum()),
            "groups_ge2": int((x >= 2).sum()), "groups_ge5": int((x >= 5).sum()),
            "groups_ge10": int((x >= 10).sum()), "groups_ge50": int((x >= 50).sum()),
        })
    pd.DataFrame(rows).to_csv(AUDIT / f"{suffix}_multiplicity_summary.csv", index=False)


def concentration(df: pd.DataFrame) -> None:
    rows = []
    for label, sub in df.groupby("label"):
        counts = sub.groupby("site_key_private").size().sort_values(ascending=False).to_numpy()
        n, total = len(counts), counts.sum()
        gini = (2 * np.sum(np.arange(1, n + 1) * np.sort(counts)) / (n * total) - (n + 1) / n) if n else np.nan
        csum = np.cumsum(counts) / total
        rows.append({"label": int(label), "top1_share": counts[:1].sum()/total,
                     "top10_share": counts[:10].sum()/total, "top100_share": counts[:100].sum()/total,
                     "gini": gini, "sites_cover_50pct": int(np.searchsorted(csum, .5)+1),
                     "sites_cover_90pct": int(np.searchsorted(csum, .9)+1)})
    pd.DataFrame(rows).to_csv(AUDIT / "site_concentration.csv", index=False)


def structural(df: pd.DataFrame, name: str) -> None:
    binary = ["root_only", "query_present", "www", "is_ip", "punycode", "encoded", "is_shortener"]
    numeric = ["url_length", "hostname_length", "path_length", "subdomain_depth"]
    rows = []
    for label, sub in df.groupby("label"):
        row = {"label": int(label), "rows": len(sub), "sites": sub.site_key_private.nunique(),
               "https_rate": (sub.scheme == "https").mean()}
        row.update({f"{c}_rate": float(sub[c].fillna(False).mean()) for c in binary})
        for c in numeric:
            row[f"{c}_mean"] = float(sub[c].mean())
            row[f"{c}_median"] = float(sub[c].median())
        rows.append(row)
    pd.DataFrame(rows).to_csv(AUDIT / f"structural_fairness_{name}.csv", index=False)
    tld = df.groupby(["label", "public_suffix_private"]).size().rename("rows").reset_index()
    tld["class_total"] = tld.groupby("label").rows.transform("sum")
    tld["within_class_share"] = tld.rows / tld.class_total
    tld.to_csv(AUDIT / f"tld_by_class_{name}.csv", index=False)


def cap_groups(df: pd.DataFrame, cap: int) -> pd.DataFrame:
    return (df.assign(_rank=df.groupby(["label", "site_key_private"])["normalized_url_hash"].rank(method="first"))
              .query("_rank <= @cap").drop(columns="_rank"))


def exposure(df: pd.DataFrame, name: str) -> None:
    rows = []
    idx = np.arange(len(df))
    for seed in SEEDS:
        train_idx, rest_idx = train_test_split(idx, test_size=.30, random_state=seed, stratify=df.label)
        val_idx, test_idx = train_test_split(rest_idx, test_size=.50, random_state=seed,
                                             stratify=df.iloc[rest_idx].label)
        tr, te = df.iloc[train_idx], df.iloc[test_idx]
        for label in [0, 1]:
            sub = te[te.label == label]
            rows.append({"corpus": name, "seed": seed, "label": label, "test_rows": len(sub),
                         "hostname_seen_rate": sub.hostname_ascii.isin(set(tr.hostname_ascii)).mean(),
                         "site_seen_rate": sub.site_key_private.isin(set(tr.site_key_private)).mean(),
                         "shared_hostnames": sub.hostname_ascii[sub.hostname_ascii.isin(set(tr.hostname_ascii))].nunique(),
                         "shared_sites": sub.site_key_private[sub.site_key_private.isin(set(tr.site_key_private))].nunique()})
    pd.DataFrame(rows).to_csv(AUDIT / f"random_split_exposure_{name}.csv", index=False)


def greedy_site_split(df: pd.DataFrame, seed: int, key: str) -> pd.DataFrame:
    groups = df.groupby(key).agg(rows=("record_id", "size"), positives=("label", "sum")).reset_index()
    rng = np.random.default_rng(seed)
    groups["tie"] = rng.random(len(groups))
    groups = groups.sort_values(["rows", "tie"], ascending=[False, True])
    targets = {"train": .70 * len(df), "validation": .15 * len(df), "test": .15 * len(df)}
    assigned = {"train": 0, "validation": 0, "test": 0}
    mapping = {}
    for row in groups.itertuples(index=False):
        split = min(assigned, key=lambda s: assigned[s] / targets[s])
        mapping[getattr(row, key)] = split
        assigned[split] += row.rows
    out = df[["record_id", "label", "hostname_ascii", "site_key_icann", "site_key_private"]].copy()
    out["split"] = out[key].map(mapping)
    out["protocol_key"] = key
    out["seed"] = seed
    return out


def splits(df: pd.DataFrame) -> None:
    summaries = []
    split_dir = AUDIT / "candidate_splits"
    split_dir.mkdir(exist_ok=True)
    for key, protocol in [("hostname_ascii", "hostname"), ("site_key_icann", "icann"), ("site_key_private", "private")]:
        for seed in SEEDS:
            out = greedy_site_split(df, seed, key)
            path = split_dir / f"candidate_{protocol}_seed{seed}.parquet"
            out.to_parquet(path, index=False)
            for split, sub in out.groupby("split"):
                summaries.append({"protocol": protocol, "seed": seed, "split": split, "rows": len(sub),
                                  "phishing": int(sub.label.sum()), "benign": int((sub.label == 0).sum()),
                                  "hostnames": sub.hostname_ascii.nunique(), "sites_private": sub.site_key_private.nunique()})
            sets = {s: set(out.loc[out.split == s, key]) for s in ["train", "validation", "test"]}
            assert not sets["train"] & sets["validation"]
            assert not sets["train"] & sets["test"]
            assert not sets["validation"] & sets["test"]
    pd.DataFrame(summaries).to_csv(AUDIT / "candidate_split_summary.csv", index=False)


def template_audit(df: pd.DataFrame) -> None:
    def key(url: str) -> str:
        x = url.lower()
        x = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "<uuid>", x)
        x = re.sub(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "<email>", x)
        x = re.sub(r"\d{5,}", "<num>", x)
        x = re.sub(r"(?<=[=/._-])[a-z0-9_-]{20,}(?=[$&/?#._-])", "<token>", x)
        return hash_text(x)
    temp = df[["record_id", "label", "site_key_private", "normalized_url"]].copy()
    temp["template_hash"] = temp.normalized_url.map(key)
    agg = temp.groupby("template_hash").agg(rows=("record_id", "size"), sites=("site_key_private", "nunique"),
                                               labels=("label", "nunique")).reset_index()
    agg[agg.sites > 1].to_csv(AUDIT / "cross_site_template_overlap.csv", index=False)
    temp.drop(columns="normalized_url").to_parquet(AUDIT / "template_keys.parquet", index=False)


def main() -> None:
    PROC.mkdir(parents=True, exist_ok=True); AUDIT.mkdir(parents=True, exist_ok=True); MAN.mkdir(parents=True, exist_ok=True)
    p, b = read_sources()
    p.to_parquet(BASE / "raw/phishing/raw_phishing_records.parquet", index=False)
    b.to_parquet(BASE / "raw/benign/raw_benign_records.parquet", index=False)
    raw = pd.concat([p, b], ignore_index=True)
    raw.to_parquet(BASE / "manifests/combined_raw_manifest.parquet", index=False)
    parsed = parse_frame(raw)
    parsed.to_parquet(PROC / "parsed_combined_corpus.parquet", index=False)
    validity(parsed); duplicate_audit(parsed)
    dns = parsed[parsed.parse_status.isin(VALID_DNS)].copy()
    # Exact/normalized cross-label conflicts and any mixed-label site are quarantined from primary candidates.
    conflict_norm = set(dns.groupby("normalized_url_hash").label.nunique().loc[lambda x: x > 1].index)
    mixed_sites = set(dns.groupby("site_key_private").label.nunique().loc[lambda x: x > 1].index)
    eligible = dns[~dns.normalized_url_hash.isin(conflict_norm) & ~dns.site_key_private.isin(mixed_sites)].copy()
    eligible = eligible.sort_values(["label", "site_key_private", "normalized_url_hash"]).drop_duplicates("normalized_url_hash")
    eligible.to_parquet(PROC / "dns_eligible_uncapped.parquet", index=False)
    multiplicity_table(eligible, "hostname_ascii", "hostname")
    multiplicity_table(eligible, "site_key_private", "site")
    concentration(eligible); structural(eligible, "uncapped")
    for cap in [5, 10]:
        capped = cap_groups(eligible, cap)
        capped.to_parquet(PROC / f"dns_eligible_cap{cap}.parquet", index=False)
        multiplicity_table(capped, "site_key_private", f"site_cap{cap}")
        structural(capped, f"cap{cap}")
        exposure(capped, f"cap{cap}")
    approved = cap_groups(eligible, 5).copy()
    approved.to_parquet(PROC / "candidate_primary_cap5.parquet", index=False)
    splits(approved); template_audit(approved)
    hashes = {str(p.relative_to(ROOT)): sha256(p) for p in [RAW_P, RAW_B,
        BASE / "raw/phishing/raw_phishing_records.parquet", BASE / "raw/benign/raw_benign_records.parquet",
        BASE / "manifests/combined_raw_manifest.parquet", PROC / "parsed_combined_corpus.parquet",
        PROC / "candidate_primary_cap5.parquet"]}
    write_json(MAN / "phase2b_artifact_hashes.json", hashes)
    print(json.dumps({"raw_rows": len(parsed), "phishing": len(p), "benign": len(b),
                      "eligible_dns": len(eligible), "candidate_cap5": len(approved),
                      "mixed_sites_quarantined": len(mixed_sites), "cross_label_norm_conflicts": len(conflict_norm)}, indent=2))


if __name__ == "__main__":
    main()
