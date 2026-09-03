from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BASE = ROOT / "data_phase2c"
FRAME = BASE / "raw/benign/tranco_selected_frame_v1.csv"
FRAME_MANIFEST = BASE / "manifests/tranco_selected_frame_v1_manifest.json"
STATE_DIR = BASE / "acquisition"
CHUNK_DIR = BASE / "raw/benign/commoncrawl_chunks"
STATE = STATE_DIR / "site_request_state.csv"
COMPLETED = STATE_DIR / "completed_sites.csv"
FAILED = STATE_DIR / "failed_sites.csv"
PENDING = STATE_DIR / "pending_sites.csv"
MANIFEST = BASE / "manifests/commoncrawl_acquisition_manifest.json"
CRAWL_ID = "CC-MAIN-2026-30"
ENDPOINT = f"https://index.commoncrawl.org/{CRAWL_ID}-index"
USER_AGENT = "SaraArif-PhishingResearch/2.0 (academic URL-index audit; sequential checkpointed requests)"
STATE_FIELDS = [
    "site_frame_id", "tranco_rank", "tranco_domain", "request_started_at",
    "request_finished_at", "request_status", "records_returned", "retry_count", "error_type",
]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_site_num(site_id: str) -> int:
    if not site_id:
        return 0
    match = re.fullmatch(r"tfv1:(\d{6})", site_id)
    if not match:
        raise SystemExit(f"Malformed site_frame_id '{site_id}': must match pattern 'tfv1:NNNNNN'")
    return int(match.group(1))


def atomic_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, path)


def load_frame() -> tuple[list[dict], dict]:
    manifest = json.loads(FRAME_MANIFEST.read_text(encoding="utf-8"))
    if sha256(FRAME) != manifest["frame_sha256"]:
        raise SystemExit("Immutable Tranco frame hash mismatch")
    with FRAME.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh)), manifest


def load_state(frame: list[dict]) -> list[dict]:
    if STATE.exists():
        with STATE.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        if [r["site_frame_id"] for r in rows] != [r["selection_row_id"] for r in frame]:
            raise SystemExit("Checkpoint state does not match immutable frame ordering")
        return rows
    rows = [{
        "site_frame_id": r["selection_row_id"], "tranco_rank": r["tranco_rank"],
        "tranco_domain": r["tranco_domain"], "request_started_at": "",
        "request_finished_at": "", "request_status": "PENDING", "records_returned": "0",
        "retry_count": "0", "error_type": "",
    } for r in frame]
    atomic_csv(STATE, rows, STATE_FIELDS)
    return rows


def write_views(rows: list[dict]) -> None:
    atomic_csv(STATE, rows, STATE_FIELDS)
    atomic_csv(COMPLETED, [r for r in rows if r["request_status"] == "COMPLETED"], STATE_FIELDS)
    atomic_csv(FAILED, [r for r in rows if r["request_status"] == "FAILED"], STATE_FIELDS)
    atomic_csv(PENDING, [r for r in rows if r["request_status"] == "PENDING"], STATE_FIELDS)


def query_site(row: dict, limit: int, timeout: int, retries: int, backoff: float) -> tuple[list[dict], int, str]:
    params = urllib.parse.urlencode([
        ("url", row["tranco_domain"]), ("matchType", "domain"), ("output", "json"),
        ("filter", "status:200"), ("filter", "mime:text/html"),
        ("collapse", "urlkey"), ("limit", str(limit)),
    ])
    request = urllib.request.Request(f"{ENDPOINT}?{params}", headers={"User-Agent": USER_AGENT})
    last_error = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                text = response.read().decode("utf-8", errors="replace")
            records = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                records.append({
                    "site_frame_id": row["site_frame_id"], "tranco_rank": int(row["tranco_rank"]),
                    "tranco_domain": row["tranco_domain"], "crawl_id": CRAWL_ID,
                    "url": item.get("url"), "urlkey": item.get("urlkey"),
                    "crawl_timestamp": item.get("timestamp"), "status": item.get("status"),
                    "mime": item.get("mime"), "mime_detected": item.get("mime-detected"),
                    "digest": item.get("digest"), "record_id": item.get("recordid"),
                    "warc_filename": item.get("filename"), "warc_offset": item.get("offset"),
                    "warc_length": item.get("length"),
                })
            return records, attempt, ""
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP_{exc.code}"
            if exc.code == 404:
                return [], attempt, ""
        except urllib.error.URLError as exc:
            last_error = f"URL_ERROR:{type(exc.reason).__name__}"
        except TimeoutError:
            last_error = "TIMEOUT"
        except Exception as exc:
            last_error = type(exc).__name__
        if attempt < retries:
            time.sleep(backoff * (2 ** attempt))
    return [], retries, last_error


def write_chunk(row: dict, records: list[dict]) -> Path:
    path = CHUNK_DIR / f"{row['site_frame_id'].replace(':', '_')}.jsonl"
    if path.exists():
        raise RuntimeError(f"Refusing to overwrite existing chunk: {path.name}")
    tmp = path.with_suffix(".jsonl.tmp")
    with tmp.open("x", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(tmp, path)
    return path


def summarize(rows: list[dict], frame_manifest: dict, args: argparse.Namespace, started: str) -> dict:
    completed = [r for r in rows if r["request_status"] == "COMPLETED"]
    failed = [r for r in rows if r["request_status"] == "FAILED"]
    pending = [r for r in rows if r["request_status"] == "PENDING"]
    chunks = sorted(CHUNK_DIR.glob("*.jsonl"))
    chunk_hashes = [{"file": p.name, "sha256": sha256(p), "bytes": p.stat().st_size} for p in chunks]
    total_records = sum(int(r["records_returned"] or 0) for r in completed)
    result = {
        "source": "Common Crawl CDXJ URL Index", "crawl_id": CRAWL_ID,
        "endpoint": ENDPOINT, "frame_file": FRAME.name,
        "frame_sha256": frame_manifest["frame_sha256"], "frame_rows": frame_manifest["row_count"],
        "query_contract": {"matchType": "domain", "status": "200", "mime": "text/html",
                           "collapse": "urlkey", "per_site_limit": args.urls_per_site,
                           "body_downloaded": False, "warc_downloaded": False},
        "execution_contract": {"workers": 1, "inter_request_delay_seconds": args.delay,
                               "timeout_seconds": args.timeout, "retry_limit": args.retries,
                               "exponential_backoff_base_seconds": args.backoff,
                               "candidate_limit": args.candidate_limit},
        "run_started_at_utc": started, "manifest_updated_at_utc": now(),
        "completed_sites": len(completed), "failed_sites": len(failed), "pending_sites": len(pending),
        "sites_with_records": sum(int(r["records_returned"] or 0) > 0 for r in completed),
        "candidate_records": total_records, "chunks": chunk_hashes,
        "checkpoint_hashes": {p.name: sha256(p) for p in [STATE, COMPLETED, FAILED, PENDING]},
        "status": "COMPLETE" if not pending else "INCOMPLETE",
    }
    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, MANIFEST)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-sites-this-run", type=int, default=25)
    parser.add_argument("--urls-per-site", type=int, default=50)
    parser.add_argument("--candidate-limit", type=int, default=100000)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--backoff", type=float, default=2.0)
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--circuit-breaker", type=int, default=3)
    parser.add_argument("--start-site-id", type=str, default="", help="Optional lower acquisition site_frame_id boundary (e.g. tfv1:001880)")
    args = parser.parse_args()

    start_num = parse_site_num(args.start_site_id) if args.start_site_id else 0

    for directory in [STATE_DIR, CHUNK_DIR, MANIFEST.parent]:
        directory.mkdir(parents=True, exist_ok=True)
    frame, frame_manifest = load_frame()
    if args.start_site_id:
        if not any(r["selection_row_id"] == args.start_site_id for r in frame):
            raise SystemExit(f"Requested --start-site-id '{args.start_site_id}' not found in Tranco frame")
    if MANIFEST.exists():
        previous = json.loads(MANIFEST.read_text(encoding="utf-8"))
        locked = previous["query_contract"]
        if previous["crawl_id"] != CRAWL_ID or previous["frame_sha256"] != frame_manifest["frame_sha256"]:
            raise SystemExit("Acquisition source/frame contract differs from existing checkpoint manifest")
        if int(locked["per_site_limit"]) != args.urls_per_site:
            raise SystemExit("Per-site candidate limit differs from existing checkpoint manifest")
        if int(previous["execution_contract"]["candidate_limit"]) != args.candidate_limit:
            raise SystemExit("Global candidate limit differs from existing checkpoint manifest")
    rows = load_state(frame)
    if args.retry_failed:
        for row in rows:
            if row["request_status"] == "FAILED":
                row.update({"request_status": "PENDING", "error_type": ""})
        write_views(rows)

    if args.start_site_id:
        skipped_pending = [r for r in rows if r["request_status"] == "PENDING" and parse_site_num(r["site_frame_id"]) < start_num]
        print(json.dumps({
            "start_site_governance": "ACTIVE",
            "requested_start_site": args.start_site_id,
            "skipped_earlier_pending_count": len(skipped_pending),
            "skipped_site_ids": [r["site_frame_id"] for r in skipped_pending],
        }), flush=True)

    started = now()
    processed = 0
    consecutive_failures = 0
    current_records = sum(int(r["records_returned"] or 0) for r in rows if r["request_status"] == "COMPLETED")
    for row in rows:
        if row["request_status"] != "PENDING":
            continue
        row_num = parse_site_num(row["site_frame_id"])
        if start_num > 0 and row_num < start_num:
            continue
        if processed >= args.max_sites_this_run or current_records >= args.candidate_limit:
            break
        row["request_started_at"] = now()
        records, retry_count, error = query_site(row, args.urls_per_site, args.timeout, args.retries, args.backoff)
        row["request_finished_at"] = now()
        row["retry_count"] = str(retry_count)
        row["records_returned"] = str(len(records))
        if error:
            row["request_status"] = "FAILED"
            row["error_type"] = error
            consecutive_failures += 1
        else:
            write_chunk(row, records)
            row["request_status"] = "COMPLETED"
            row["error_type"] = ""
            current_records += len(records)
            consecutive_failures = 0
        processed += 1
        write_views(rows)
        summary = summarize(rows, frame_manifest, args, started)
        print(json.dumps({"processed_this_run": processed, "site": row["site_frame_id"],
                          "status": row["request_status"], "records": len(records),
                          "totals": {k: summary[k] for k in ["completed_sites", "failed_sites", "pending_sites", "candidate_records"]}}), flush=True)
        if consecutive_failures >= args.circuit_breaker:
            print(json.dumps({"circuit_breaker": "OPEN", "consecutive_failures": consecutive_failures}), flush=True)
            break
        time.sleep(args.delay)
    print(json.dumps(summarize(rows, frame_manifest, args, started), indent=2))


if __name__ == "__main__":
    main()
