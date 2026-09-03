from __future__ import annotations

import argparse
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd
import requests

from phase2b_common import ROOT, sha256


CRAWL_ID = "CC-MAIN-2026-30"
ENDPOINT = f"https://index.commoncrawl.org/{CRAWL_ID}-index"
TRANCO = ROOT / "data_phase2b/raw/benign/tranco_26J39_top1m.csv"
OUT_DIR = ROOT / "data_phase2b/raw/benign"
MANIFEST_DIR = ROOT / "data_phase2b/manifests"
LOCK = threading.Lock()


def fetch_site(rank: int, domain: str, limit: int) -> list[dict]:
    params = [
        ("url", domain), ("matchType", "domain"), ("output", "json"),
        ("filter", "status:200"), ("filter", "mime:text/html"),
        ("collapse", "urlkey"), ("limit", str(limit)),
    ]
    headers = {"User-Agent": "SaraArif-PhishingResearch/1.0 (academic URL-index audit)"}
    for attempt in range(4):
        try:
            response = requests.get(ENDPOINT, params=params, headers=headers, timeout=45)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            rows = []
            for line in response.text.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                rows.append({
                    "raw_url": item.get("url"), "crawl_id": CRAWL_ID,
                    "crawl_timestamp": item.get("timestamp"),
                    "status": item.get("status"), "mime": item.get("mime"),
                    "mime_detected": item.get("mime-detected"),
                    "digest": item.get("digest"), "record_id": item.get("recordid"),
                    "filename": item.get("filename"), "offset": item.get("offset"),
                    "length": item.get("length"), "tranco_rank": rank,
                    "tranco_domain": domain,
                })
            return rows
        except Exception:
            if attempt == 3:
                return []
            time.sleep(1.5 * (2 ** attempt))
    return []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-sites", type=int, default=3000)
    ap.add_argument("--urls-per-site", type=int, default=10)
    ap.add_argument("--rank-min", type=int, default=10001)
    ap.add_argument("--rank-max", type=int, default=500000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    tranco = pd.read_csv(TRANCO, names=["rank", "domain"])
    eligible = tranco[(tranco["rank"] >= args.rank_min) & (tranco["rank"] <= args.rank_max)]
    rng = random.Random(args.seed)
    chosen = rng.sample(list(eligible.itertuples(index=False, name=None)), args.max_sites)
    frame = pd.DataFrame(chosen, columns=["tranco_rank", "tranco_domain"]).sort_values("tranco_rank")
    frame.to_csv(OUT_DIR / "tranco_selected_site_frame.csv", index=False)
    rows, completed = [], 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(fetch_site, int(rank), domain, args.urls_per_site): (rank, domain)
                   for rank, domain in chosen}
        for fut in as_completed(futures):
            rows.extend(fut.result())
            completed += 1
            if completed % 250 == 0:
                print(json.dumps({"sites_completed": completed, "candidate_urls": len(rows)}), flush=True)
    out = pd.DataFrame(rows)
    if len(out):
        out = out.drop_duplicates(subset=["raw_url", "crawl_timestamp", "record_id"])
    parquet = OUT_DIR / "commoncrawl_CC-MAIN-2026-30_candidates.parquet"
    out.to_parquet(parquet, index=False)
    manifest = {
        "source": "Common Crawl URL Index", "crawl_id": CRAWL_ID,
        "endpoint": ENDPOINT, "crawl_from": "2026-07-10T07:05:34Z",
        "crawl_to": "2026-07-23T01:13:28Z", "query_match_type": "domain",
        "filters": ["status:200", "mime:text/html"], "collapse": "urlkey",
        "body_downloaded": False, "warc_downloaded": False,
        "tranco_list_id": "26J39", "rank_range": [args.rank_min, args.rank_max],
        "seed": args.seed, "requested_sites": args.max_sites,
        "sites_with_results": int(out.tranco_domain.nunique()) if len(out) else 0,
        "candidate_rows": int(len(out)), "urls_per_site_query_cap": args.urls_per_site,
        "workers": args.workers, "output_file": parquet.name,
        "output_sha256": sha256(parquet), "acquisition_date": "2026-08-17",
    }
    (MANIFEST_DIR / "commoncrawl_source_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2), flush=True)


if __name__ == "__main__":
    main()
