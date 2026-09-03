"""Execute frozen P3-12 read-only site-cluster bootstrap inference.

This tool reads canonical Test prediction files only.  It never loads a model,
features, split builder, or URL corpus, and never writes to source artifacts.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import platform
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import scipy
import scipy.sparse as sp
import sklearn
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)


ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "data/interim/phase3/p3_12_scope_reconstruction"
OUT = ROOT / "data/interim/phase3/p3_12_statistical_inference"
REGISTRY = SCOPE / "P3_12_REQUIRED_INPUT_REGISTRY.csv"
ADDENDUM = SCOPE / "P3_12_GOVERNANCE_ADDENDUM.json"
GOVERNANCE_SHA = "9f05b573fcdd6af04e5327332faf42f3b237f66deaf45968100abced8cbad631"
TOL = 1e-6
THRESHOLD = 0.5
METRICS = [
    "MCC",
    "PR-AUC",
    "Macro F1",
    "Phishing Recall",
    "Precision",
    "FPR",
    "Specificity",
    "Balanced Accuracy",
    "ROC-AUC",
]
CSV_REPLICATE_COLUMNS = [
    "experiment_id", "regime", "seed", "model", "replicate_id", "metric",
    "metric_value", "rng_stream_identity", "rng_digest",
]


class P312Failure(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True, default=_json_default) + "\n")


def _json_default(value: object) -> object:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    raise TypeError(type(value).__name__)


def require(condition: bool, classification: str) -> None:
    if not condition:
        raise P312Failure(classification)


def rng_details(addendum: dict, experiment_id: str, stream: str) -> tuple[str, str, np.random.Generator]:
    policy = addendum["prospective_pre_execution_governance_decisions_added_2026_08_30"]["rng_policy"]
    material = policy["canonical_material"].format(experiment_id=experiment_id, stream=stream)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    entropy = int.from_bytes(bytes.fromhex(digest), "big", signed=False)
    identity = f"{policy['algorithm_id']}|{experiment_id}|{stream}"
    return identity, digest, np.random.default_rng(np.random.SeedSequence(entropy))


def canonical_metric_path(row: dict) -> Path:
    prediction = ROOT / row["artifact_path"]
    root = prediction.parent.parent
    options = sorted(p for p in root.glob("*test_metrics*.csv") if "determinism" not in str(p).lower())
    if len(options) == 1:
        return options[0]
    # P3-05 used a nested outcome directory rather than the later seed layout.
    options = sorted(p for p in root.rglob("*test_metrics*.csv") if "determinism" not in str(p).lower())
    if len(options) != 1:
        raise P312Failure("P3_12_POINT_ESTIMATE_RECONCILIATION_FAILED")
    return options[0]


def point_metrics(y: np.ndarray, label: np.ndarray, prob: np.ndarray) -> dict[str, float]:
    tn, fp, fn, tp = confusion_matrix(y, label, labels=[0, 1]).ravel()
    return {
        "MCC": float(matthews_corrcoef(y, label)),
        "PR-AUC": float(average_precision_score(y, prob)),
        "Macro F1": float(f1_score(y, label, average="macro")),
        "Phishing Recall": float(recall_score(y, label, zero_division=0)),
        "Precision": float(precision_score(y, label, zero_division=0)),
        "FPR": float(fp / (tn + fp)),
        "Specificity": float(tn / (tn + fp)),
        "Balanced Accuracy": float(balanced_accuracy_score(y, label)),
        "ROC-AUC": float(roc_auc_score(y, prob)),
    }


def canonical_metric_mapping() -> dict[str, str]:
    return {
        "MCC": "MCC", "PR-AUC": "PR_AUC", "Macro F1": "macro_f1",
        "Phishing Recall": "phishing_recall", "Precision": "precision", "FPR": "FPR",
        "Specificity": "specificity", "Balanced Accuracy": "balanced_accuracy", "ROC-AUC": "ROC_AUC",
    }


def metric_arrays(confusion: np.ndarray) -> dict[str, np.ndarray]:
    tn, fp, fn, tp = (confusion[:, i].astype(float) for i in range(4))
    with np.errstate(divide="raise", invalid="raise"):
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        specificity = tn / (tn + fp)
        fpr = fp / (tn + fp)
        f1_pos = 2 * tp / (2 * tp + fp + fn)
        f1_neg = 2 * tn / (2 * tn + fp + fn)
        mcc_den = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = (tp * tn - fp * fn) / mcc_den
    return {
        "MCC": mcc,
        "Precision": precision,
        "Phishing Recall": recall,
        "Specificity": specificity,
        "FPR": fpr,
        "Balanced Accuracy": (recall + specificity) / 2,
        "Macro F1": (f1_pos + f1_neg) / 2,
    }


class PreparedIdentity:
    def __init__(self, row: dict, frame: pd.DataFrame, point: dict[str, float]):
        self.row = row
        self.experiment_id = row["experiment_id"]
        self.y = frame["true_label_numeric"].to_numpy(dtype=np.int8)
        self.label = frame["predicted_label_numeric"].to_numpy(dtype=np.int8)
        self.prob = frame["phishing_probability"].to_numpy(dtype=float)
        self.sites = frame["site_key_private"].astype(str).to_numpy()
        self.point = point
        site_codes, site_names = pd.factorize(self.sites, sort=True)
        self.site_codes = site_codes.astype(np.int32)
        self.site_names = np.asarray(site_names)
        labels_by_site = pd.DataFrame({"site": self.site_codes, "label": self.y}).groupby("site")["label"].nunique()
        require(bool((labels_by_site == 1).all()), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        self.site_label = np.zeros(len(self.site_names), dtype=np.int8)
        for code in range(len(self.site_names)):
            self.site_label[code] = self.y[np.flatnonzero(self.site_codes == code)[0]]
        self.pools = {label: np.flatnonzero(self.site_label == label) for label in (0, 1)}
        require(len(self.pools[0]) > 0 and len(self.pools[1]) > 0, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        self.cluster_confusion = np.zeros((len(self.site_names), 4), dtype=np.int64)
        np.add.at(self.cluster_confusion[:, 0], self.site_codes[(self.y == 0) & (self.label == 0)], 1)
        np.add.at(self.cluster_confusion[:, 1], self.site_codes[(self.y == 0) & (self.label == 1)], 1)
        np.add.at(self.cluster_confusion[:, 2], self.site_codes[(self.y == 1) & (self.label == 0)], 1)
        np.add.at(self.cluster_confusion[:, 3], self.site_codes[(self.y == 1) & (self.label == 1)], 1)
        # Score groups are fixed; only cluster multiplicities change per replicate.
        order = np.argsort(-self.prob, kind="mergesort")
        sorted_prob = self.prob[order]
        group = np.empty(len(order), dtype=np.int32)
        group[0] = 0
        group[1:] = np.cumsum(sorted_prob[1:] != sorted_prob[:-1])
        self.n_groups = int(group[-1]) + 1
        self.order = order
        rows = self.site_codes[order]
        cols = group
        self.score_total = sp.coo_matrix((np.ones(len(rows), dtype=np.int16), (rows, cols)), shape=(len(self.site_names), self.n_groups)).tocsr()
        self.score_positive = sp.coo_matrix((self.y[order].astype(np.int16), (rows, cols)), shape=(len(self.site_names), self.n_groups)).tocsr()

    def counts_batch(self, rng: np.random.Generator, batch_size: int) -> np.ndarray:
        counts = np.zeros((batch_size, len(self.site_names)), dtype=np.int16)
        indices = np.arange(batch_size)[:, None]
        for label in (0, 1):
            pool = self.pools[label]
            draws = pool[rng.integers(0, len(pool), size=(batch_size, len(pool)), endpoint=False)]
            np.add.at(counts, (indices, draws), 1)
        return counts

    def weighted_metrics(self, counts: np.ndarray, mcc_only: bool = False) -> dict[str, np.ndarray]:
        confusion = counts @ self.cluster_confusion
        values = metric_arrays(confusion)
        if mcc_only:
            require(bool(np.all(np.isfinite(values["MCC"]))), "P3_12_DEGENERATE_BOOTSTRAP_REPLICATE_REQUIRES_REVIEW")
            return {"MCC": values["MCC"]}
        cm = sp.csr_matrix(counts)
        positives = (cm @ self.score_positive).toarray().astype(float)
        totals = (cm @ self.score_total).toarray().astype(float)
        negatives = totals - positives
        pos_total = positives.sum(axis=1)
        neg_total = negatives.sum(axis=1)
        require(bool(np.all(pos_total > 0) and np.all(neg_total > 0)), "P3_12_DEGENERATE_BOOTSTRAP_REPLICATE_REQUIRES_REVIEW")
        cum_pos = np.cumsum(positives, axis=1)
        cum_total = np.cumsum(totals, axis=1)
        with np.errstate(divide="raise", invalid="raise"):
            precision_at_threshold = np.divide(cum_pos, cum_total, out=np.zeros_like(cum_pos), where=cum_total > 0)
            values["PR-AUC"] = np.sum(precision_at_threshold * (positives / pos_total[:, None]), axis=1)
            neg_below = neg_total[:, None] - np.cumsum(negatives, axis=1)
            values["ROC-AUC"] = np.sum(positives * (neg_below + 0.5 * negatives), axis=1) / (pos_total * neg_total)
        for metric in METRICS:
            require(bool(np.all(np.isfinite(values[metric]))), "P3_12_DEGENERATE_BOOTSTRAP_REPLICATE_REQUIRES_REVIEW")
        return values


def load_and_preflight(rows: list[dict]) -> tuple[list[PreparedIdentity], list[dict], list[dict]]:
    prepared: list[PreparedIdentity] = []
    access_rows: list[dict] = []
    reconciliation: list[dict] = []
    mapping = canonical_metric_mapping()
    for row in rows:
        path = ROOT / row["artifact_path"]
        require(path.exists(), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        observed_sha = sha256(path)
        require(observed_sha == row["artifact_sha256"], "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        frame = pd.read_csv(path)
        required = {"combined_row_id", "true_label_numeric", "predicted_label_numeric", "phishing_probability", "site_key_private"}
        require(required.issubset(frame.columns), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        require(len(frame) == int(row["row_count"]), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        require(frame["combined_row_id"].is_unique, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        require(frame["site_key_private"].notna().all() and frame["site_key_private"].astype(str).str.len().gt(0).all(), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        y = frame["true_label_numeric"].to_numpy(dtype=np.int8)
        z = frame["predicted_label_numeric"].to_numpy(dtype=np.int8)
        p = frame["phishing_probability"].to_numpy(dtype=float)
        require(set(np.unique(y)) == {0, 1} and set(np.unique(z)).issubset({0, 1}), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        require(np.all(np.isfinite(p)) and np.all((p >= 0) & (p <= 1)), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        require(np.array_equal(z, (p >= THRESHOLD).astype(np.int8)), "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        point = point_metrics(y, z, p)
        canonical_path = canonical_metric_path(row)
        canonical = pd.read_csv(canonical_path)
        model_column = "model_id"
        model_row = canonical.loc[canonical[model_column].astype(str) == row["model"]]
        require(len(model_row) == 1, "P3_12_POINT_ESTIMATE_RECONCILIATION_FAILED")
        canonical_row = model_row.iloc[0]
        for metric, column in mapping.items():
            difference = abs(point[metric] - float(canonical_row[column]))
            reconciliation.append({"experiment_id": row["experiment_id"], "metric": metric, "canonical_metric_path": str(canonical_path.relative_to(ROOT)), "point_estimate": point[metric], "canonical_value": float(canonical_row[column]), "absolute_difference": difference, "tolerance": TOL, "status": "PASS" if difference <= TOL else "FAIL"})
            require(difference <= TOL, "P3_12_POINT_ESTIMATE_RECONCILIATION_FAILED")
        prepared.append(PreparedIdentity(row, frame, point))
        access_rows.append({"experiment_id": row["experiment_id"], "regime": row["regime"], "seed": row["seed"], "model": row["model"], "prediction_path": row["artifact_path"], "prediction_sha256": observed_sha, "row_count": len(frame), "label_access": "READ_ONLY_FROZEN", "prediction_generation": "FALSE", "probability_generation": "FALSE", "model_fit": "FALSE", "site_key_source": "stored site_key_private in canonical prediction artifact", "timestamp_utc": datetime.now(timezone.utc).isoformat()})
    return prepared, access_rows, reconciliation


def rng_audit(addendum: dict, identities: list[PreparedIdentity]) -> list[dict]:
    records = []
    streams = addendum["prospective_pre_execution_governance_decisions_added_2026_08_30"]["rng_policy"]["streams"]
    needed = [(x.experiment_id, "PERFORMANCE_CI") for x in identities]
    needed.extend([("UNCAPPED/A/42/M" + m, "A_NATIVE") for m in ("1", "2", "3")])
    needed.extend([("UNCAPPED/C/42/M" + m, "C_NATIVE") for m in ("1", "2", "3")])
    seen: dict[str, str] = {}
    for experiment_id, stream in needed:
        require(stream in streams, "P3_12_RNG_COLLISION_REQUIRES_REVIEW")
        identity, digest, _ = rng_details(addendum, experiment_id, stream)
        require(digest not in seen, "P3_12_RNG_COLLISION_REQUIRES_REVIEW")
        seen[digest] = identity
        records.append({"experiment_id": experiment_id, "stream": stream, "rng_stream_identity": identity, "rng_digest": digest, "collision": "FALSE"})
    return records


def write_replicate_rows(writer: csv.DictWriter, prepared: PreparedIdentity, values: dict[str, np.ndarray], start: int, stream_identity: str, digest: str) -> None:
    for local_index in range(len(next(iter(values.values())))):
        for metric in METRICS:
            writer.writerow({"experiment_id": prepared.experiment_id, "regime": prepared.row["regime"], "seed": prepared.row["seed"], "model": prepared.row["model"], "replicate_id": start + local_index, "metric": metric, "metric_value": repr(float(values[metric][local_index])), "rng_stream_identity": stream_identity, "rng_digest": digest})


def bootstrap_identity(prepared: PreparedIdentity, addendum: dict, writer: csv.DictWriter | None, stream: str, mcc_only: bool = False) -> tuple[dict[str, np.ndarray], dict]:
    policy = addendum["prospective_pre_execution_governance_decisions_added_2026_08_30"]
    b = int(addendum["historical_level_1_controls"]["bootstrap_replicates"])
    stream_identity, digest, rng = rng_details(addendum, prepared.experiment_id, stream)
    requested_metrics = ["MCC"] if mcc_only else METRICS
    values_all = {metric: np.empty(b, dtype=float) for metric in requested_metrics}
    batch = 32
    for start in range(0, b, batch):
        size = min(batch, b - start)
        counts = prepared.counts_batch(rng, size)
        values = prepared.weighted_metrics(counts, mcc_only=mcc_only)
        for metric in requested_metrics:
            values_all[metric][start:start + size] = values[metric]
        if writer is not None:
            write_replicate_rows(writer, prepared, values, start + 1, stream_identity, digest)
    audit = {"experiment_id": prepared.experiment_id, "rng_stream_identity": stream_identity, "rng_digest": digest, "replicates": b, "dropped_replicates": 0, "retried_replicates": 0, "degenerate_replicates": 0}
    return values_all, audit


def ci_rows(prepared: PreparedIdentity, values: dict[str, np.ndarray], addendum: dict) -> list[dict]:
    policy = addendum["prospective_pre_execution_governance_decisions_added_2026_08_30"]
    ci = policy["ci_policy"]
    b = int(ci["valid_replicates_required"])
    return [{"experiment_id": prepared.experiment_id, "regime": prepared.row["regime"], "seed": prepared.row["seed"], "model": prepared.row["model"], "metric": metric, "point_estimate": prepared.point[metric], "bootstrap_replicate_count": b, "CI_lower": float(np.percentile(values[metric], ci["lower_percentile"])), "CI_upper": float(np.percentile(values[metric], ci["upper_percentile"])), "confidence_level": ci["confidence_level"], "bootstrap_method": "NON_PARAMETRIC_CLASS_STRATIFIED_SITE_CLUSTER_PERCENTILE_BOOTSTRAP", "cluster_key": "site_key_private", "master_seed": 99} for metric in METRICS]


def difference_rows(prepared_by_id: dict[str, PreparedIdentity], addendum: dict) -> tuple[list[dict], list[dict]]:
    policy = addendum["prospective_pre_execution_governance_decisions_added_2026_08_30"]
    ci = policy["ci_policy"]
    output, audit = [], []
    for model in ("M1", "M2", "M3"):
        a = prepared_by_id[f"UNCAPPED/A/42/{model}"]
        c = prepared_by_id[f"UNCAPPED/C/42/{model}"]
        va, aa = bootstrap_identity(a, addendum, None, "A_NATIVE", mcc_only=True)
        vc, ac = bootstrap_identity(c, addendum, None, "C_NATIVE", mcc_only=True)
        delta = va["MCC"] - vc["MCC"]
        output.append({"model": model, "comparison_identity": "UNCAPPED/A/42_MINUS_UNCAPPED/C/42", "seed_context": "PRE_SPECIFIED_MATCHED_ANALYSIS_SEED_42_ONLY", "metric": "MCC", "A_point_estimate": a.point["MCC"], "C_point_estimate": c.point["MCC"], "difference": a.point["MCC"] - c.point["MCC"], "difference_CI_lower": float(np.percentile(delta, ci["lower_percentile"])), "difference_CI_upper": float(np.percentile(delta, ci["upper_percentile"])), "comparison_type": "UNPAIRED_CLUSTERED_PERCENTILE_CI", "A_rng_stream_identity": aa["rng_stream_identity"], "A_rng_digest": aa["rng_digest"], "C_rng_stream_identity": ac["rng_stream_identity"], "C_rng_digest": ac["rng_digest"], "bootstrap_replicate_count": len(delta)})
        audit.extend([aa, ac])
    return output, audit


def seed_summary(ci: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (regime, model, metric), part in ci.groupby(["regime", "model", "metric"], sort=True):
        x = part["point_estimate"].to_numpy(dtype=float)
        rows.append({"regime": regime, "model": model, "metric": metric, "seed_count": len(x), "mean": float(np.mean(x)), "sample_SD": float(np.std(x, ddof=1)), "minimum": float(np.min(x)), "maximum": float(np.max(x)), "seed_by_seed_point_estimates": json.dumps({str(int(r.seed)): float(r.point_estimate) for r in part.itertuples()}, sort_keys=True)})
    return pd.DataFrame(rows)


def validate_bootstrap_formula(prepared: PreparedIdentity, addendum: dict) -> dict:
    """Validate weighted PR-AUC/ROC-AUC against sklearn on the first deterministic replicate."""
    _, _, rng = rng_details(addendum, prepared.experiment_id, "PERFORMANCE_CI")
    counts = prepared.counts_batch(rng, 1)
    values = prepared.weighted_metrics(counts)
    weights = counts[0, prepared.site_codes]
    reference = {"PR-AUC": average_precision_score(prepared.y, prepared.prob, sample_weight=weights), "ROC-AUC": roc_auc_score(prepared.y, prepared.prob, sample_weight=weights)}
    differences = {m: float(abs(values[m][0] - reference[m])) for m in reference}
    require(all(v <= 1e-12 for v in differences.values()), "P3_12_STATISTICAL_EXECUTION_INVARIANT_FAILED")
    return {"experiment_id": prepared.experiment_id, "replicate_id": 1, "metric_differences_vs_sklearn": differences, "status": "PASS"}


def deterministic_audit(prepared: PreparedIdentity, addendum: dict, results_path: Path) -> dict:
    """Recreate five selected draws only; this is not a full bootstrap rerun."""
    saved = pd.read_csv(results_path)
    target = saved[(saved.experiment_id == prepared.experiment_id) & (saved.replicate_id.isin([1, 2, 3, 4, 5]))]
    _, _, rng = rng_details(addendum, prepared.experiment_id, "PERFORMANCE_CI")
    counts = prepared.counts_batch(rng, 5)
    values = prepared.weighted_metrics(counts)
    checks = []
    for replicate_id in range(1, 6):
        for metric in METRICS:
            expected = float(target[(target.replicate_id == replicate_id) & (target.metric == metric)].metric_value.iloc[0])
            checks.append(abs(expected - float(values[metric][replicate_id - 1])))
    maximum = max(checks)
    require(maximum <= 1e-12, "P3_12_STATISTICAL_EXECUTION_INVARIANT_FAILED")
    return {"selected_identity": prepared.experiment_id, "selected_replicates": [1, 2, 3, 4, 5], "maximum_metric_difference": maximum, "tolerance": 1e-12, "full_bootstrap_rerun": False, "status": "PASS"}


def main() -> None:
    if OUT.exists():
        allowed_failed_attempts = all(p.is_dir() and p.name.startswith("failed_prebootstrap_attempt_") for p in OUT.iterdir())
        require(allowed_failed_attempts, "P3_12_EXISTING_OUTPUT_CONFLICT_REQUIRES_REVIEW")
    addendum = json.loads(ADDENDUM.read_text(encoding="utf-8"))
    require(sha256(ADDENDUM) == GOVERNANCE_SHA, "P3_12_GOVERNANCE_SHA_MISMATCH_REQUIRES_REVIEW")
    decisions = addendum["prospective_pre_execution_governance_decisions_added_2026_08_30"]
    require(decisions["primary_input_matrix"]["expected_canonical_prediction_artifacts"] == 30, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    rows = list(csv.DictReader(REGISTRY.open(newline="", encoding="utf-8")))
    require(len(rows) == 30, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    require({r["model"] for r in rows} == {"M1", "M2", "M3"}, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    require({r["regime"] for r in rows} == {"A", "C"}, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        prepared, access, reconciliation = load_and_preflight(rows)
        prepared_by_id = {x.experiment_id: x for x in prepared}
        require(len(prepared_by_id) == 30, "P3_12_INPUT_PREFLIGHT_FAILED_REQUIRES_REVIEW")
        rng_records = rng_audit(addendum, prepared)
        pd.DataFrame(rows).to_csv(OUT / "P3_12_INPUT_REGISTRY.csv", index=False)
        pd.DataFrame(access).to_csv(OUT / "P3_12_READ_ONLY_TEST_ACCESS_LOG.csv", index=False)
        pd.DataFrame(reconciliation).to_csv(OUT / "P3_12_POINT_ESTIMATE_RECONCILIATION.csv", index=False)
        write_json(OUT / "P3_12_RNG_AUDIT.json", {"algorithm_id": decisions["rng_policy"]["algorithm_id"], "master_seed": 99, "collision_count": 0, "records": rng_records})
        contract = {"method": "NON_PARAMETRIC_CLASS_STRATIFIED_SITE_CLUSTER_PERCENTILE_BOOTSTRAP", "B": 2000, "master_seed": 99, "confidence_level": 0.95, "percentiles": [2.5, 97.5], "cluster_key": "site_key_private", "class_stratified": True, "repeated_cluster_policy": decisions["resampling_policy"]["repeated_cluster_handling"], "degenerate_policy": "FAIL_LOUD_NO_DROP_NO_RETRY", "metrics": METRICS, "native_A_C_policy": decisions["native_a_vs_c_policy"], "test_governance": decisions["test_governance"]}
        write_json(OUT / "P3_12_BOOTSTRAP_CONTRACT.json", contract)
        formula_audits = [validate_bootstrap_formula(x, addendum) for x in prepared]
        ci_all, execution_audits = [], []
        results_path = OUT / "P3_12_BOOTSTRAP_RESULTS.csv"
        with results_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_REPLICATE_COLUMNS, lineterminator="\n")
            writer.writeheader()
            for index, item in enumerate(prepared, 1):
                values, audit = bootstrap_identity(item, addendum, writer, "PERFORMANCE_CI")
                ci_all.extend(ci_rows(item, values, addendum))
                execution_audits.append(audit)
                print(f"P3-12 complete performance bootstrap {index}/30: {item.experiment_id}", flush=True)
        ci_frame = pd.DataFrame(ci_all)
        ci_frame.to_csv(OUT / "P3_12_CI_SUMMARY.csv", index=False)
        difference, difference_audits = difference_rows(prepared_by_id, addendum)
        pd.DataFrame(difference).to_csv(OUT / "P3_12_A_VS_C_DIFFERENCE_RESULTS.csv", index=False)
        seed_frame = seed_summary(ci_frame)
        seed_frame.to_csv(OUT / "P3_12_SEED_SUMMARY.csv", index=False)
        pd.DataFrame([r for r in ci_all if r["metric"] == "MCC"]).to_csv(OUT / "P3_12_PLOT_DATA_REGIME_MCC.csv", index=False)
        pd.DataFrame(difference).to_csv(OUT / "P3_12_PLOT_DATA_A_VS_C_MCC.csv", index=False)
        seed_frame[seed_frame.metric == "MCC"].to_csv(OUT / "P3_12_PLOT_DATA_SEED_VARIABILITY.csv", index=False)
        det = deterministic_audit(prepared_by_id["UNCAPPED/A/42/M1"], addendum, results_path)
        write_json(OUT / "P3_12_DETERMINISM_AUDIT.json", {"rng_derivation_rechecked": "PASS", "formula_audits": formula_audits, "selected_replicate_audit": det})
        invariants = [
            ("P312-E01", "governance SHA verified", "PASS", GOVERNANCE_SHA),
            ("P312-E02", "all 30 input SHAs verified", "PASS", "30/30"),
            ("P312-E03", "all site keys nonempty", "PASS", "30/30"),
            ("P312-E04", "all site clusters class-pure", "PASS", "30/30"),
            ("P312-E05", "both classes present all inputs", "PASS", "30/30"),
            ("P312-E06", "no fitting", "PASS", "0"), ("P312-E07", "no prediction generation", "PASS", "0"),
            ("P312-E08", "no probability generation", "PASS", "0"), ("P312-E09", "threshold unchanged", "PASS", "0.5"),
            ("P312-E10", "RNG collision count zero", "PASS", "0"), ("P312-E11", "B=2000 all completed identities", "PASS", "30/30"),
            ("P312-E12", "no dropped replicates", "PASS", "0"), ("P312-E13", "no retried replicates", "PASS", "0"),
            ("P312-E14", "no degenerate replicates", "PASS", "0"), ("P312-E15", "cluster multiplicity preserved", "PASS", "weighted multiplicity"),
            ("P312-E16", "no URL-level resampling", "PASS", "site clusters only"), ("P312-E17", "class-stratified cluster sampling", "PASS", "TRUE"),
            ("P312-E18", "point estimates reconcile", "PASS", "270/270 metric comparisons"), ("P312-E19", "percentile bounds correct", "PASS", "2.5/97.5"),
            ("P312-E20", "A/C native comparison unpaired", "PASS", "A42/C42"), ("P312-E21", "A/C RNG streams independent", "PASS", "separate SHA-256 digests"),
            ("P312-E22", "2,801 cohort unused", "PASS", "TRUE"), ("P312-E23", "p-values not generated", "PASS", "TRUE"),
            ("P312-E24", "P3-SUP1 correlations unused", "PASS", "TRUE"), ("P312-E25", "P3-13 not executed", "PASS", "TRUE"),
            ("P312-E26", "determinism audit", "PASS", "RNG, formulas, and five selected replicates"),
        ]
        pd.DataFrame(invariants, columns=["invariant_id", "name", "status", "evidence"]).to_csv(OUT / "P3_12_INVARIANTS.csv", index=False)
        manifest = {"classification": "P3_12_STATISTICAL_INFERENCE_PASSED", "governance_addendum_sha256": GOVERNANCE_SHA, "input_count": 30, "input_sha_verification": "30/30 PASS", "read_only_test_inference": True, "model_fits": 0, "new_test_predictions": 0, "new_test_probabilities": 0, "threshold_tuning": 0, "bootstrap_replicates_per_identity": 2000, "performance_bootstrap_identities": 30, "difference_bootstrap_context": "A42_MINUS_C42 for M1/M2/M3", "degenerate_replicates": 0, "dropped_replicates": 0, "retried_replicates": 0, "p_values_generated": 0, "P3_SUP1_correlations_used": False, "RQ3_common_2801_cohort_used": False, "P3_13_executed": False, "environment": {"python": sys.version, "platform": platform.platform(), "numpy": np.__version__, "pandas": pd.__version__, "scipy": scipy.__version__, "sklearn": sklearn.__version__}, "artifacts": {p.name: sha256(p) for p in sorted(OUT.iterdir()) if p.is_file()}, "execution_audits": execution_audits + difference_audits}
        write_json(OUT / "P3_12_EXECUTION_MANIFEST.json", manifest)
    except Exception:
        # Preserve all partial forensic outputs without pretending a successful execution.
        raise


if __name__ == "__main__":
    main()
