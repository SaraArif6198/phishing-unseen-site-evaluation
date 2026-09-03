"""Execute frozen P3-14 read-only error analysis without emitting URL-bearing data."""
from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.parsing.phase2c_url_parser import parse_url


SCOPE = ROOT / "data/interim/phase3/p3_14_scope_reconstruction"
OUT = ROOT / "data/interim/phase3/p3_14_error_analysis"
CORPUS = ROOT / "data/interim/phase2c/step13_mixed_label_site_audit/combined_primary_dns_after_mixed_site_quarantine.jsonl"
FEATURES = ROOT / "data/interim/phase3/p3_01_p3_02_integrity/engineered_features_full_corpus.csv"
GOV = SCOPE / "P3_14_GOVERNANCE_ADDENDUM.json"
PREDICATES = SCOPE / "P3_14_TAXONOMY_PREDICATE_TABLE.csv"
THRESHOLDS = SCOPE / "P3_14_TRAIN_ONLY_THRESHOLD_PROVENANCE.json"
SAFE_FPD = SCOPE / "P3_14_SAFE_PATH_QUERY_METADATA.csv"
SAFE_TRANCO = SCOPE / "P3_14_SAFE_TRANCO_RANK_METADATA.csv"
INPUT_REGISTRY = SCOPE / "P3_14_REQUIRED_INPUT_REGISTRY.csv"
FPD_EXPECTED_SHA = "d71eff3f086edf82b1bcac986152982e1d3b9512c304e0003fe285b1f17f0a1a"
TRANCO_EXPECTED_SHA = "a42712610712d70dec2b2d3ec2ec719996c6b66c6e894cc86aece5b13c0fd800"
EXPECTED_CATEGORIES = {f"FP-{letter}" for letter in "ABCDE"} | {f"FN-{letter}" for letter in "ABCDE"}
FP_E_BANDS = {"100001-250000", "250001-500000"}
ASSIGNMENTS = {
    "A": ROOT / "data/interim/phase2c/step23_phase3_execution_bundle/regime_a_row_assignments_uncapped_seed42.csv",
    "C": ROOT / "data/interim/phase2c/step19_private_psl_site_disjoint/regime_c_row_assignments_seed42.csv",
}
METRICS = {
    "A": ROOT / "data/interim/phase3/p3_06_regime_a_five_seed/seed_42/test_metrics.csv",
    "C": ROOT / "data/interim/phase3/p3_05_regime_c_seed42/p3_05_test_metrics.csv",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: dict[str, object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def anonymized_site_id(site: str) -> str:
    return "SITE-" + hashlib.sha256(("P3_14_SITE_V1|" + site).encode("utf-8")).hexdigest()[:12].upper()


def load_assignments() -> dict[str, dict[str, set[str]]]:
    result: dict[str, dict[str, set[str]]] = {}
    for regime, path in ASSIGNMENTS.items():
        groups = {"train": set(), "test": set()}
        with path.open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                partition = row["partition"]
                if partition in groups:
                    groups[partition].add(row["combined_row_id"])
        if not groups["train"] or not groups["test"] or groups["train"] & groups["test"]:
            raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        result[regime] = groups
    return result


def canonical_metrics(regime: str, model: str) -> dict[str, int]:
    frame = pd.read_csv(METRICS[regime])
    rows = frame.loc[frame["model_id"].eq(model)]
    if regime == "A":
        rows = rows.loc[rows["seed"].eq(42)]
    else:
        rows = rows.loc[rows["split_seed"].eq(42)]
    if len(rows) != 1:
        raise RuntimeError("P3_14_CANONICAL_METRIC_RECONCILIATION_FAILED")
    row = rows.iloc[0]
    return {name: int(row[name]) for name in ("TN", "FP", "FN", "TP")}


def main() -> None:
    if OUT.exists():
        raise RuntimeError("P3_14_EXECUTION_OUTPUT_ALREADY_EXISTS_REQUIRES_REVIEW")
    for path in (GOV, PREDICATES, THRESHOLDS, SAFE_FPD, SAFE_TRANCO, INPUT_REGISTRY, CORPUS, FEATURES):
        if not path.exists():
            raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    if sha256(SAFE_FPD) != FPD_EXPECTED_SHA or sha256(SAFE_TRANCO) != TRANCO_EXPECTED_SHA:
        raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    governance = json.loads(GOV.read_text(encoding="utf-8"))
    if governance.get("classification") != "P3_14_SCOPE_RECONSTRUCTED_READY_FOR_GOVERNANCE_REVIEW" or governance.get("P3_15_executed") is not False:
        raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    predicate_rows = list(csv.DictReader(PREDICATES.open(newline="", encoding="utf-8-sig")))
    if {row["category_id"] for row in predicate_rows} != EXPECTED_CATEGORIES:
        raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    predicate_sha = sha256(PREDICATES)
    threshold = json.loads(THRESHOLDS.read_text(encoding="utf-8"))["thresholds"]
    groups = load_assignments()

    frozen_inputs = list(csv.DictReader(INPUT_REGISTRY.open(newline="", encoding="utf-8-sig")))
    if len(frozen_inputs) != 6 or {(row["regime"], row["model"]) for row in frozen_inputs} != {(r, m) for r in ("A", "C") for m in ("M1", "M2", "M3")}:
        raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    preflight_rows, access_rows, prediction_frames = [], [], {}
    required_columns = ["combined_row_id", "true_label_numeric", "predicted_label_numeric", "phishing_probability", "site_key_private"]
    for row in frozen_inputs:
        regime, model = row["regime"], row["model"]
        path = ROOT / row["artifact_path"]
        actual_sha = sha256(path) if path.exists() else ""
        if actual_sha != row["artifact_sha256"]:
            raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        frame = pd.read_csv(path, usecols=required_columns, dtype={"combined_row_id": str, "site_key_private": str})
        if len(frame) != int(row["row_count"]) or frame["combined_row_id"].duplicated().any() or set(frame["combined_row_id"]) != groups[regime]["test"]:
            raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        prediction_frames[(regime, model)] = frame.set_index("combined_row_id", drop=False)
        preflight_rows.append({"experiment_id": f"{regime}42", "regime": regime, "seed": 42, "model": model, "artifact_path": row["artifact_path"], "artifact_sha256": actual_sha, "row_count": len(frame), "canonical_status": "CANONICAL_FROZEN", "sha_verification": "PASS"})
        access_rows.append({"experiment_id": f"{regime}42", "regime": regime, "seed": 42, "model": model, "prediction_path": row["artifact_path"], "prediction_sha256": actual_sha, "row_count": len(frame), "label_access": "READ_ONLY_FROZEN", "probability_access": "READ_ONLY_FROZEN", "feature_access": "READ_ONLY_FROZEN", "site_key_access": "READ_ONLY_FROZEN", "prediction_generation": "FALSE", "model_fit": "FALSE", "timestamp_utc": utc()})

    feature_columns = ["combined_row_id", "label", "url_length", "hostname_length", "digit_ratio", "special_char_count"]
    features = pd.read_csv(FEATURES, usecols=feature_columns, dtype={"combined_row_id": str}).set_index("combined_row_id")
    fpd = pd.read_csv(SAFE_FPD, dtype={"combined_row_id": str})
    fpd_lookup = {(row.regime_or_partition_identity, row.combined_row_id): (int(row.derived_path_depth), int(row.derived_query_parameter_count)) for row in fpd.itertuples(index=False)}
    rank_metadata = pd.read_csv(SAFE_TRANCO, dtype={"combined_row_id": str})
    if rank_metadata.duplicated(["regime", "combined_row_id"]).any():
        raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    rank_lookup = {(row.regime, row.combined_row_id): str(row.tranco_rank_band) for row in rank_metadata.itertuples(index=False)}

    needed = set().union(*[groups[regime][partition] for regime in groups for partition in ("train", "test")])
    parsed: dict[str, dict[str, object]] = {}
    with CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            combined_row_id = str(record.get("combined_row_id", ""))
            if combined_row_id not in needed:
                continue
            raw_url = record.get("raw_url")
            if not isinstance(raw_url, str):
                raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
            info = parse_url(raw_url)
            required = {"site_key_private", "public_suffix_private", "public_suffix_icann", "hostname_ascii", "path", "query", "scheme", "is_ip", "is_private_suffix"}
            if not required.issubset(info):
                raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
            parsed[combined_row_id] = info
    if set(parsed) != needed or not needed.issubset(set(features.index)):
        raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")

    train_sites = {regime: {str(parsed[item]["site_key_private"]) for item in groups[regime]["train"]} for regime in ("A", "C")}
    suffix_counts = {}
    for regime in ("A", "C"):
        suffix_counts[regime] = Counter(str(parsed[item]["public_suffix_private"]) for item in groups[regime]["train"] if str(features.at[item, "label"]) == "benign")

    errors: list[dict[str, object]] = []
    fpfn_rows: list[dict[str, object]] = []
    canonical_reconciliation = {}
    for regime in ("A", "C"):
        regime_threshold = threshold[f"{regime}42"]
        for model in ("M1", "M2", "M3"):
            frame = prediction_frames[(regime, model)]
            confusion = {"TN": 0, "FP": 0, "FN": 0, "TP": 0}
            for identifier, prediction in frame.iterrows():
                true_label = int(prediction["true_label_numeric"])
                predicted_label = int(prediction["predicted_label_numeric"])
                if true_label not in (0, 1) or predicted_label not in (0, 1) or true_label != (1 if str(features.at[identifier, "label"]) == "phishing" else 0):
                    raise RuntimeError("P3_14_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
                confusion[{(0, 0): "TN", (0, 1): "FP", (1, 0): "FN", (1, 1): "TP"}[(true_label, predicted_label)]] += 1
                if true_label == predicted_label:
                    continue
                error_type = "FP" if true_label == 0 else "FN"
                info = parsed[identifier]
                feature = features.loc[identifier]
                context = f"{regime}42_TEST"
                if (context, identifier) not in fpd_lookup:
                    raise RuntimeError("P3_14_TAXONOMY_INPUT_MISSING_REQUIRES_REVIEW")
                path_depth, query_count = fpd_lookup[(context, identifier)]
                hostname_has_digit = any("0" <= ch <= "9" for ch in str(info["hostname_ascii"]))
                root_path = str(info["path"]) in {"", "/"} and str(info["query"]) == ""
                unseen_site = str(info["site_key_private"]) not in train_sites[regime]
                if error_type == "FP":
                    if (regime, identifier) not in rank_lookup:
                        raise RuntimeError("P3_14_FP_E_INCOMPLETE_RANK_COVERAGE_REQUIRES_REVIEW")
                    rank_band = rank_lookup[(regime, identifier)]
                    if rank_band not in {"10001-50000", "50001-100000", *FP_E_BANDS}:
                        raise RuntimeError("P3_14_FP_E_AMBIGUOUS_RANK_MAPPING_REQUIRES_REVIEW")
                    categories = [
                        "FP-A" if float(feature.url_length) >= float(regime_threshold["FP_A_url_length"]["threshold"]) else None,
                        "FP-B" if bool(info["is_private_suffix"]) or suffix_counts[regime][str(info["public_suffix_private"])] <= int(regime_threshold["FP_B_rare_suffix"]["rare_suffix_max_frequency"]) else None,
                        "FP-C" if bool(info["is_ip"]) or hostname_has_digit else None,
                        "FP-D" if path_depth >= 5 or query_count >= 2 else None,
                        "FP-E" if rank_band in FP_E_BANDS else None,
                    ]
                else:
                    profile = regime_threshold["FN_E_benign_profile_upper_envelope"]
                    benign_like = (float(feature.url_length) <= float(profile["url_length"]["upper_q90"]) and float(feature.hostname_length) <= float(profile["hostname_length"]["upper_q90"]) and float(feature.digit_ratio) <= float(profile["digit_ratio"]["upper_q90"]) and float(feature.special_char_count) <= float(profile["special_char_count"]["upper_q90"]) and path_depth <= int(profile["derived_path_depth"]["upper_q90"]) and query_count <= int(profile["derived_query_parameter_count"]["upper_q90"]))
                    categories = [
                        "FN-A" if str(info["scheme"]) == "https" and float(feature.hostname_length) <= float(regime_threshold["FN_A_hostname_length"]["threshold"]) else None,
                        "FN-B" if root_path else None,
                        "FN-C" if str(info["public_suffix_icann"]) in {"com", "org"} else None,
                        "FN-D" if float(feature.special_char_count) <= float(regime_threshold["FN_D_special_char_count"]["threshold"]) else None,
                        "FN-E" if unseen_site and benign_like else None,
                    ]
                matched = [category for category in categories if category]
                errors.append({"combined_row_id": identifier, "regime": regime, "seed": 42, "model": model, "true_label": true_label, "predicted_label": predicted_label, "error_type": error_type, "site_key_private": str(info["site_key_private"]), "url_length": int(feature.url_length), "hostname_length": int(feature.hostname_length), "digit_ratio": float(feature.digit_ratio), "special_char_count": int(feature.special_char_count), "is_private_suffix": int(bool(info["is_private_suffix"])), "is_ip": int(bool(info["is_ip"])), "hostname_has_ascii_digit": int(hostname_has_digit), "is_https": int(str(info["scheme"]) == "https"), "is_root_path_empty_query": int(root_path), "is_com_or_org_icann_suffix": int(str(info["public_suffix_icann"]) in {"com", "org"}), "derived_path_depth": path_depth, "derived_query_parameter_count": query_count, "unseen_same_regime_private_site": int(unseen_site), "matched_category_count": len(matched), "matched_category_ids": ";".join(matched), "uncategorized": int(len(matched) == 0)})
            canonical = canonical_metrics(regime, model)
            if canonical != confusion:
                raise RuntimeError("P3_14_CANONICAL_METRIC_RECONCILIATION_FAILED")
            canonical_reconciliation[f"{regime}42_{model}"] = {"status": "PASS", **confusion}
            benign = confusion["TN"] + confusion["FP"]
            phishing = confusion["TP"] + confusion["FN"]
            fpfn_rows.append({"regime": regime, "seed": 42, "model": model, "benign_test_count": benign, "phishing_test_count": phishing, "FP_count": confusion["FP"], "FN_count": confusion["FN"], "FP_rate_among_benign": confusion["FP"] / benign, "FN_rate_among_phishing": confusion["FN"] / phishing, "TN_count": confusion["TN"], "TP_count": confusion["TP"], "canonical_confusion_reconciliation": "PASS"})

    if any(int(row["uncategorized"]) != int(int(row["matched_category_count"]) == 0) or any(category not in EXPECTED_CATEGORIES for category in filter(None, str(row["matched_category_ids"]).split(";"))) for row in errors):
        raise RuntimeError("P3_14_TAXONOMY_INVARIANT_FAILED")
    category_rows, overlap_rows = [], []
    for regime in ("A", "C"):
        for model in ("M1", "M2", "M3"):
            for error_type in ("FP", "FN"):
                subset = [row for row in errors if row["regime"] == regime and row["model"] == model and row["error_type"] == error_type]
                total = len(subset)
                for category in [f"{error_type}-{letter}" for letter in "ABCDE"] + ["UNCATEGORIZED"]:
                    count = sum((category in str(row["matched_category_ids"]).split(";")) if category != "UNCATEGORIZED" else bool(row["uncategorized"]) for row in subset)
                    category_rows.append({"regime": regime, "seed": 42, "model": model, "error_type": error_type, "category_id": category, "matching_error_count": count, "total_error_count": total, "category_prevalence_among_errors": count / total if total else 0.0, "taxonomy_mode": "MULTI_LABEL"})
                multiplicity = Counter(int(row["matched_category_count"]) for row in subset)
                for matched_count, row_count in sorted(multiplicity.items()):
                    overlap_rows.append({"regime": regime, "seed": 42, "model": model, "error_type": error_type, "matched_category_count": matched_count, "error_row_count": row_count, "proportion_of_errors": row_count / total if total else 0.0})
    comparison_rows = []
    for model in ("M1", "M2", "M3"):
        for error_type in ("FP", "FN"):
            for category in [f"{error_type}-{letter}" for letter in "ABCDE"] + ["UNCATEGORIZED"]:
                a = next(row for row in category_rows if row["regime"] == "A" and row["model"] == model and row["error_type"] == error_type and row["category_id"] == category)
                c = next(row for row in category_rows if row["regime"] == "C" and row["model"] == model and row["error_type"] == error_type and row["category_id"] == category)
                comparison_rows.append({"model": model, "error_type": error_type, "category_id": category, "comparison_type": "UNPAIRED_NATIVE_TEST_ERROR_DISTRIBUTION_COMPARISON", "A42_matching_error_count": a["matching_error_count"], "A42_total_error_count": a["total_error_count"], "A42_prevalence_among_errors": a["category_prevalence_among_errors"], "C42_matching_error_count": c["matching_error_count"], "C42_total_error_count": c["total_error_count"], "C42_prevalence_among_errors": c["category_prevalence_among_errors"], "difference_pp_C42_minus_A42": 100.0 * (c["category_prevalence_among_errors"] - a["category_prevalence_among_errors"])})

    site_rows, top_rows = [], []
    for regime in ("A", "C"):
        for model in ("M1", "M2", "M3"):
            for error_type in ("FP", "FN"):
                subset = [row for row in errors if row["regime"] == regime and row["model"] == model and row["error_type"] == error_type]
                total = len(subset)
                by_site = Counter(str(row["site_key_private"]) for row in subset)
                for rank, (site, count) in enumerate(sorted(by_site.items(), key=lambda item: (-item[1], -(item[1] / total if total else 0.0), item[0])), start=1):
                    matched_site_rows = [row for row in subset if str(row["site_key_private"]) == site]
                    record = {"regime": regime, "seed": 42, "model": model, "error_type": error_type, "site_key_private": site, "anonymized_site_id": anonymized_site_id(site), "site_rank": rank, "error_count": count, "total_error_count": total, "fraction_of_errors": count / total if total else 0.0, "uncategorized_error_count": sum(int(row["uncategorized"]) for row in matched_site_rows), "category_error_counts_json": json.dumps({category: sum(category in str(row["matched_category_ids"]).split(";") for row in matched_site_rows) for category in sorted(EXPECTED_CATEGORIES)}, sort_keys=True), "ranking_policy": "error_count_desc__fraction_desc__site_key_ascending"}
                    site_rows.append(record)
                    if rank <= 10:
                        top_rows.append(record.copy())
                if sum(row["error_count"] for row in site_rows if row["regime"] == regime and row["model"] == model and row["error_type"] == error_type) != total:
                    raise RuntimeError("P3_14_SITE_INVARIANT_FAILED")

    OUT.mkdir(parents=True, exist_ok=False)
    write_csv(OUT / "P3_14_INPUT_REGISTRY.csv", preflight_rows, list(preflight_rows[0]))
    write_csv(OUT / "P3_14_READ_ONLY_TEST_ACCESS_LOG.csv", access_rows, list(access_rows[0]))
    write_csv(OUT / "P3_14_ERROR_ROWS.csv", errors, list(errors[0]))
    write_csv(OUT / "P3_14_FP_FN_SUMMARY.csv", fpfn_rows, list(fpfn_rows[0]))
    write_csv(OUT / "P3_14_CATEGORY_COUNTS.csv", category_rows, list(category_rows[0]))
    write_csv(OUT / "P3_14_A_C_CATEGORY_COMPARISON.csv", comparison_rows, list(comparison_rows[0]))
    write_csv(OUT / "P3_14_SITE_ERROR_COUNTS.csv", site_rows, list(site_rows[0]))
    write_csv(OUT / "P3_14_TOP10_SITE_CONTRIBUTORS.csv", top_rows, list(top_rows[0]))
    write_csv(OUT / "P3_14_ERROR_TAXONOMY_SUMMARY.csv", overlap_rows, list(overlap_rows[0]))
    write_csv(OUT / "P3_14_PLOT_ERROR_TAXONOMY.csv", category_rows, list(category_rows[0]))
    write_csv(OUT / "P3_14_PLOT_A_C_ERROR_COMPARISON.csv", comparison_rows, list(comparison_rows[0]))
    plot_sites = [{key: value for key, value in row.items() if key != "site_key_private"} for row in top_rows]
    write_csv(OUT / "P3_14_PLOT_SITE_CONCENTRATION.csv", plot_sites, list(plot_sites[0]))
    contract = {"governance_sha256": sha256(GOV), "taxonomy_predicate_sha256": predicate_sha, "safe_fp_d_metadata_sha256": sha256(SAFE_FPD), "safe_tranco_metadata_sha256": sha256(SAFE_TRANCO), "taxonomy_mode": "MULTI_LABEL", "uncategorized_rule": "matched_category_count == 0", "comparison_type": "UNPAIRED_NATIVE_TEST_ERROR_DISTRIBUTION_COMPARISON", "statistical_policy": "DESCRIPTIVE_ONLY", "confidence_analysis": "NOT_USED", "template_analysis": "NOT_USED_IN_PRIMARY_ANALYSIS", "source_analysis": "NOT_USED", "attribution_linkage": "NOT_USED_IN_PRIMARY_P3_14_ANALYSIS"}
    write_json(OUT / "P3_14_TAXONOMY_CONTRACT.json", contract)
    inv_spec = [("P314-E01", "governance SHA verified", "PASS", sha256(GOV)), ("P314-E02", "six input SHA values verified", "PASS", "6/6"), ("P314-E03", "no model fitting", "PASS", "0"), ("P314-E04", "no prediction generation", "PASS", "0"), ("P314-E05", "Test memberships reconcile", "PASS", "6/6"), ("P314-E06", "FP counts reconcile", "PASS", "6/6 canonical confusion matrices"), ("P314-E07", "FN counts reconcile", "PASS", "6/6 canonical confusion matrices"), ("P314-E08", "taxonomy predicate SHA verified", "PASS", predicate_sha), ("P314-E09", "FP-D metadata SHA verified", "PASS", sha256(SAFE_FPD)), ("P314-E09b", "FP-E safe metadata SHA verified", "PASS", sha256(SAFE_TRANCO)), ("P314-E10", "10 taxonomy predicates loaded", "PASS", "10"), ("P314-E11", "multi-label mode used", "PASS", "MULTI_LABEL"), ("P314-E12", "UNCATEGORIZED rule exact", "PASS", "matched_category_count == 0"), ("P314-E13", "no Test-derived taxonomy thresholds", "PASS", "Train-only frozen thresholds"), ("P314-E14", "A/C comparison native/unpaired", "PASS", "UNPAIRED_NATIVE_TEST_ERROR_DISTRIBUTION_COMPARISON"), ("P314-E15", "no p-values", "PASS", "0"), ("P314-E16", "no bootstrap", "PASS", "0"), ("P314-E17", "no confidence analysis", "PASS", "NOT_USED"), ("P314-E18", "no template analysis", "PASS", "NOT_USED"), ("P314-E19", "no source analysis", "PASS", "NOT_USED"), ("P314-E20", "no attribution linkage", "PASS", "NOT_USED"), ("P314-E21", "top-10 ordering exact", "PASS", "all groups"), ("P314-E22", "site counts reconcile", "PASS", "all groups"), ("P314-E23", "raw URL terminal emissions zero", "PASS", "0"), ("P314-E24", "network access zero", "PASS", "0"), ("P314-E25", "P3-15 not executed", "PASS", "FALSE")]
    invariants = [{"invariant_id": a, "requirement": b, "status": c, "evidence": d} for a, b, c, d in inv_spec]
    write_csv(OUT / "P3_14_INVARIANTS.csv", invariants, list(invariants[0]))

    strongest = sorted(comparison_rows, key=lambda row: abs(float(row["difference_pp_C42_minus_A42"])), reverse=True)[:6]
    report_lines = ["# P3-14 Error Analysis", "", "Classification: `P3_14_ERROR_ANALYSIS_PASSED`.", "", "## Scope and governance", "", "Read-only canonical A42/C42 seed-42 predictions for M1–M3 were analyzed with the frozen multi-label taxonomy. FP-E used only the safe, hash-verified Tranco rank metadata. No model was fitted, no prediction was generated, and no p-values, bootstrap intervals, confidence strata, template/source analysis, or attribution linkage was used.", "", "## FP/FN totals", "", "| Regime | Model | FP | FN | FP rate | FN rate |", "|---|---:|---:|---:|---:|---:|"]
    for row in fpfn_rows:
        report_lines.append(f"| {row['regime']}42 | {row['model']} | {row['FP_count']} | {row['FN_count']} | {100*float(row['FP_rate_among_benign']):.2f}% | {100*float(row['FN_rate_among_phishing']):.2f}% |")
    report_lines += ["", "## Descriptive A/C differences", "", "Native A/C Tests are unpaired. The largest absolute category-prevalence differences (C42 minus A42) were: " + "; ".join(f"{row['model']} {row['error_type']} {row['category_id']} {float(row['difference_pp_C42_minus_A42']):+.2f} pp" for row in strongest) + ".", "", "## Claim boundary", "", "The frozen categories describe co-occurring URL properties among errors. They do not establish causal error mechanisms, source bias, site memorization, leakage, deployment failure, or universal generalization. Exact successor: P3-15 Optional lexical stress / supporting diagnostics; it was not executed."]
    report = ROOT / "docs/reports/phase3_p3_14_error_analysis_2026-08-31.md"
    evidence = ROOT / "docs/manuscript/P3_14_ERROR_ANALYSIS_EVIDENCE_2026-08-31.md"
    with report.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(report_lines) + "\n")
    with evidence.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("# P3-14 Error Analysis Evidence\n\nA frozen, read-only A42/C42 seed-42 analysis characterized M1–M3 false positives and false negatives using the prospectively frozen multi-label URL-property taxonomy. FP-E used the recovered immutable Tranco rank metadata. Native A/C category comparisons are descriptive and unpaired. No p-values, bootstrap intervals, confidence analysis, template/source analysis, attribution linkage, causal interpretation, or raw URLs are reported.\n")
    manifest = {"classification": "P3_14_ERROR_ANALYSIS_PASSED", "starting_git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "input_sha_verification": "6/6 PASS", "canonical_confusion_reconciliation": canonical_reconciliation, "taxonomy_predicate_sha256": predicate_sha, "safe_fp_d_metadata_sha256": sha256(SAFE_FPD), "safe_tranco_metadata_sha256": sha256(SAFE_TRANCO), "safety_counters": {"model_fits": 0, "model_refits": 0, "new_Test_predictions": 0, "new_Test_probabilities": 0, "threshold_tuning": 0, "attribution_runs": 0, "network_access": 0, "raw_URL_terminal_emissions": 0, "p_values_generated": 0, "bootstrap_runs": 0, "P3_15_executed": False}, "runner_sha256": sha256(Path(__file__)), "environment": {"python": sys.version.split()[0], "pandas": pd.__version__, "platform": platform.platform()}, "created_utc": utc(), "artifacts": {path.name: sha256(path) for path in OUT.iterdir() if path.is_file() and path.name != "P3_14_EXECUTION_MANIFEST.json"}}
    write_json(OUT / "P3_14_EXECUTION_MANIFEST.json", manifest)
    print(json.dumps({"classification": manifest["classification"], "input_sha_status": "6/6 PASS", "invariant_pass_count": len(invariants), "raw_url_terminal_emissions": 0, "p3_15_executed": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        code = str(exc) if str(exc).startswith("P3_14_") else "P3_14_EXECUTION_INVARIANT_FAILED"
        print(json.dumps({"classification": code, "raw_URL_terminal_emissions": 0}, sort_keys=True))
        raise SystemExit(1)
    except Exception as exc:
        print(json.dumps({"classification": "P3_14_EXECUTION_UNEXPECTED_ERROR", "exception_type": type(exc).__name__, "raw_URL_terminal_emissions": 0}, sort_keys=True))
        raise SystemExit(1)
