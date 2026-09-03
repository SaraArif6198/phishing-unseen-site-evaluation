from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import zipfile
from pathlib import Path

import requests

from phase2b_common import ROOT, sha256


def main() -> None:
    ap = argparse.ArgumentParser(description="Freeze a permanent Tranco list as a benign site frame.")
    ap.add_argument("--list-id", default="26J39")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    url = f"https://tranco-list.eu/list/{args.list_id}/1000000"
    out = ROOT / f"data_phase2b/raw/benign/tranco_{args.list_id}_top1m.zip"
    if out.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite frozen list: {out}")
    response = requests.get(url, timeout=120, headers={"User-Agent": "SaraArif-PhishingResearch/1.0"})
    response.raise_for_status(); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(response.content)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        member = zf.namelist()[0]
        csv_out = out.with_suffix(".csv")
        csv_out.write_bytes(zf.read(member))
    manifest = {"official_url": url, "list_id": args.list_id,
                "acquired_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "zip_file": out.name, "zip_sha256": sha256(out),
                "csv_file": csv_out.name, "csv_sha256": sha256(csv_out),
                "role": "Site frame only; not a root-URL benign corpus"}
    path = ROOT / "data_phase2b/manifests/tranco_source_manifest_acquisition.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
