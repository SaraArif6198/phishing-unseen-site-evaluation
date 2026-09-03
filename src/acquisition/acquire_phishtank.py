from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import requests

from phase2b_common import ROOT, sha256


URL = "https://data.phishtank.com/data/online-valid.csv.bz2"


def main() -> None:
    ap = argparse.ArgumentParser(description="Freeze the official PhishTank online-valid feed without visiting listed URLs.")
    ap.add_argument("--output", type=Path, default=ROOT / "data_phase2b/raw/phishing/online-valid_2026-08-17.csv.bz2")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    if args.output.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite frozen snapshot: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(URL, timeout=120, headers={"User-Agent": "phishtank/sara-arif-academic-research"})
    response.raise_for_status()
    args.output.write_bytes(response.content)
    manifest = {
        "official_url": URL, "acquired_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "file": args.output.name, "bytes": args.output.stat().st_size, "sha256": sha256(args.output),
        "source_last_modified": response.headers.get("last-modified"), "source_etag": response.headers.get("etag"),
        "safety": "URLs stored as inert strings; no destination requests performed",
    }
    path = ROOT / "data_phase2b/manifests/phishing_source_manifest_acquisition.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
