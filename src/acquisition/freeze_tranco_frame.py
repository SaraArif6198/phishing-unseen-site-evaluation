from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import random
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "data_phase2b/raw/benign/tranco_26J39_top1m.csv"
OUT_DIR = ROOT / "data_phase2c/raw/benign"
FRAME = OUT_DIR / "tranco_selected_frame_v1.csv"
MANIFEST = ROOT / "data_phase2c/manifests/tranco_selected_frame_v1_manifest.json"
LIST_ID = "26J39"
SEED = 42
BANDS = [(10001, 50000), (50001, 100000), (100001, 250000), (250001, 500000)]
PER_BAND = 625


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if FRAME.exists() or MANIFEST.exists():
        raise SystemExit("Immutable v1 frame or manifest already exists; refusing to overwrite")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    domains: dict[int, str] = {}
    with SOURCE.open(newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            rank = int(row[0])
            if rank > BANDS[-1][1]:
                break
            if rank >= BANDS[0][0]:
                domains[rank] = row[1].strip().lower()

    selected: list[tuple[int, str, int, int]] = []
    rng = random.Random(SEED)
    for band_id, (lo, hi) in enumerate(BANDS, start=1):
        candidates = [(r, domains[r]) for r in range(lo, hi + 1) if r in domains]
        picks = rng.sample(candidates, PER_BAND)
        selected.extend((rank, domain, band_id, idx) for idx, (rank, domain) in enumerate(picks, start=1))
    selected.sort(key=lambda x: x[0])
    stamp = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    rule = "stratified uniform sample: 625 domains from each fixed rank band; Python random.Random(42)"
    with FRAME.open("x", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "selection_row_id", "tranco_list_id", "tranco_rank", "tranco_domain",
            "selection_seed", "selection_rule", "selection_timestamp", "rank_band",
        ])
        writer.writeheader()
        for row_id, (rank, domain, band_id, _) in enumerate(selected, start=1):
            lo, hi = BANDS[band_id - 1]
            writer.writerow({
                "selection_row_id": f"tfv1:{row_id:06d}", "tranco_list_id": LIST_ID,
                "tranco_rank": rank, "tranco_domain": domain, "selection_seed": SEED,
                "selection_rule": rule, "selection_timestamp": stamp,
                "rank_band": f"{lo}-{hi}",
            })
    manifest = {
        "artifact": FRAME.name,
        "immutable": True,
        "created_at_utc": stamp,
        "source_file": SOURCE.name,
        "source_sha256": digest(SOURCE),
        "tranco_list_id": LIST_ID,
        "selection_seed": SEED,
        "selection_rule": rule,
        "rank_bands": [{"min": lo, "max": hi, "selected": PER_BAND} for lo, hi in BANDS],
        "row_count": len(selected),
        "frame_sha256": digest(FRAME),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
