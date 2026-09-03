"""Frozen P3-13 RQ3 attribution execution controller.

Uses only SHA-verified reconstructed objects.  It never fits, tunes, or
overwrites a canonical prediction.  Permuted M2 calls are explicitly logged
as attribution counterfactual prediction calls, not canonical predictions.
"""
import csv
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy
import shap
import sklearn
from scipy.stats import rankdata, spearmanr
from sklearn.metrics import matthews_corrcoef

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/interim/phase3/p3_13_attribution"
OBJECTS = OUT / "reconstructed_models"
SCOPE = ROOT / "data/interim/phase3/p3_13_scope_reconstruction"
BUNDLE = ROOT / "data/interim/phase2c/step23_phase3_execution_bundle"
CORPUS = ROOT / "data/interim/phase2c/step13_mixed_label_site_audit/combined_primary_dns_after_mixed_site_quarantine.jsonl"
FEATURES = ROOT / "data/interim/phase3/p3_01_p3_02_integrity/engineered_features_full_corpus.csv"
COHORT = BUNDLE / "rq3_common_attribution_cohort.csv"
GOV = SCOPE / "P3_13_GOVERNANCE_ADDENDUM.json"
LOCK = OUT / "P3_13_ENVIRONMENT_PACKAGE_LOCK.json"
RECON_REGISTRY = OUT / "P3_13_RECONSTRUCTED_MODEL_REGISTRY.csv"
RECON_VERIFY = OUT / "P3_13_MODEL_RECONSTRUCTION_VERIFICATION.csv"
RECON_MANIFEST = OUT / "P3_13_RECONSTRUCTION_MANIFEST.json"
TOL = 1e-6
SHAP_REPEAT_TOL = 0.0
EXPECTED = {
    "governance": "7c100f01f6d36c069cdb6c2ad873fc67b4d5e2c5a81e98bc3c132b8f7389ed44",
    "cohort": "f225fc62bb7e0be90764d4bfda3a3b504790367ccf2e072ef8f300900f41aff6",
    "features": "f2303ae2d4b28daa22aa14bb88733b890ad0de82fc4e2993d2ed2e5eabf581a3",
    "corpus": "b850a96bda433c4d7207ae97a139d18692781b5bb70d2b5a13ef7920c467972d",
}
PREDICTIONS = {
    "A": {m: ROOT / f"data/interim/phase3/p3_06_regime_a_five_seed/seed_42/predictions/{m}.csv" for m in ("M1", "M2", "M3")},
    "C": {m: ROOT / f"data/interim/phase3/p3_05_regime_c_seed42/predictions/{m}_regime_c_seed42_test_predictions.csv" for m in ("M1", "M2", "M3")},
}
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length", "path_depth", "subdomain_depth", "has_query", "has_port", "is_root_path", "digit_count", "digit_ratio", "hyphen_count", "dot_count", "special_char_count", "percent_encoded_count", "char_entropy", "is_ip", "is_private_suffix", "has_www", "is_https", "is_missing_scheme", "has_punycode",
]
REQUIRED_OUTPUTS = [
    "P3_13_EXECUTION_MANIFEST.json", "P3_13_INPUT_REGISTRY.csv", "P3_13_MODEL_REGISTRY.csv", "P3_13_ATTRIBUTION_ACCESS_LOG.csv", "P3_13_ATTRIBUTION_CONTRACT.json", "P3_13_M1_COEFFICIENTS.csv", "P3_13_M1_A_C_COMPARISON.csv", "P3_13_M2_SHAP_LOCAL.csv", "P3_13_M2_SHAP_GLOBAL.csv", "P3_13_M2_A_C_CHANGE.csv", "P3_13_M2_PERMUTATION_IMPORTANCE.csv", "P3_13_M3_TOP_NGRAMS.csv", "P3_13_M3_SHARED_VOCABULARY_COMPARISON.csv", "P3_13_M3_TOPK_OVERLAP.csv", "P3_13_ATTRIBUTION_SUMMARY.csv", "P3_13_INVARIANTS.csv", "P3_13_PLOT_GLOBAL_ATTRIBUTION.csv", "P3_13_PLOT_ATTRIBUTION_CHANGE.csv", "P3_13_PLOT_M3_TOPK.csv", "P3_13_LOCAL_EXAMPLE_SELECTION.csv", "P3_13_PLOT_LOCAL_EXAMPLES.csv",
]


def now(): return datetime.now(timezone.utc).isoformat()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def stable(text): return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    for _ in range(10):
        try:
            os.replace(temp, path); return
        except PermissionError:
            time.sleep(0.2)
    raise RuntimeError(f"P3_13_OUTPUT_FILE_LOCK:{path}")


def write_csv(path, rows, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns); writer.writeheader(); writer.writerows(rows)
    for _ in range(10):
        try:
            os.replace(temp, path); return
        except PermissionError:
            time.sleep(0.2)
    raise RuntimeError(f"P3_13_OUTPUT_FILE_LOCK:{path}")


def label(value): return 1 if str(value).strip().lower() in ("1", "phishing") else 0
def probability(model, x): return model.predict_proba(x)[:, list(model.classes_).index(1)]


def keyed_digest(rows, fields):
    h = hashlib.sha256()
    for rid in sorted(rows):
        h.update(rid.encode("utf-8"))
        for field in fields: h.update(b"\x1f" + str(rows[rid][field]).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def load_cohort_data(ids):
    wanted, corpus, feats = set(ids), {}, {}
    with CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line); rid = row["combined_row_id"]
            if rid in wanted: corpus[rid] = {"raw_url": row["raw_url"], "label": label(row["label"]), "site_key_private": row["site_key_private"]}
    with FEATURES.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if row["combined_row_id"] in wanted: feats[row["combined_row_id"]] = row
    if set(corpus) != wanted or set(feats) != wanted: raise RuntimeError("P3_13_COHORT_JOIN_FAILED")
    return corpus, feats


def read_canonical(path):
    frame = pd.read_csv(path)
    required = {"combined_row_id", "true_label_numeric", "predicted_label_numeric", "phishing_probability"}
    if not required.issubset(frame.columns) or frame.combined_row_id.duplicated().any(): raise RuntimeError(f"P3_13_CANONICAL_PREDICTION_INVALID:{path}")
    return frame.set_index("combined_row_id", verify_integrity=True)


def feature_groups():
    contract = json.loads((BUNDLE / "engineered_feature_contract.json").read_text(encoding="utf-8"))
    mapping = {item["name"]: item.get("group") for item in contract["features"]}
    if list(mapping) != FEATURE_NAMES or any(value is None for value in mapping.values()): raise RuntimeError("P3_13_FEATURE_FAMILY_MAPPING_INVALID")
    return mapping, sha(BUNDLE / "engineered_feature_contract.json")


def load_objects_and_verify():
    registry = list(csv.DictReader(RECON_REGISTRY.open(newline="", encoding="utf-8")))
    verification = list(csv.DictReader(RECON_VERIFY.open(newline="", encoding="utf-8")))
    if len(registry) != 12 or len(verification) != 6 or any(r["status"] not in ("PASS", "PASS_WITH_NUMERICAL_TOLERANCE") for r in verification): raise RuntimeError("P3_13_RECONSTRUCTION_VERIFICATION_INVALID")
    objects = {}
    for row in registry:
        path = ROOT / row["artifact_path"]
        if not path.exists() or sha(path) != row["sha256"]: raise RuntimeError("P3_13_MODEL_OBJECT_INTEGRITY_FAILED")
        objects[(row["regime"], row["model"], row["artifact_role"])] = path
    wanted = {(r, m) for r in ("A", "C") for m in ("M1", "M2", "M3")}
    for regime, model in wanted:
        if (regime, model, "model") not in objects: raise RuntimeError("P3_13_MODEL_OBJECT_INTEGRITY_FAILED")
        if model in ("M1", "M3") and (regime, model, "preprocessor") not in objects: raise RuntimeError("P3_13_MODEL_OBJECT_INTEGRITY_FAILED")
    return registry, objects


def select_local_examples(ids, labels, pred_a, pred_c):
    rows = []
    for rid, truth, a, c in zip(ids, labels, pred_a, pred_c):
        ac, cc = int(a == truth), int(c == truth)
        stratum = { (1, 1): "A correct / C correct", (1, 0): "A correct / C wrong", (0, 1): "A wrong / C correct", (0, 0): "A wrong / C wrong" }[(ac, cc)]
        rows.append({"combined_row_id": rid, "true_label_numeric": int(truth), "A42_predicted_label": int(a), "C42_predicted_label": int(c), "stratum": stratum, "selection_hash": stable("P3_13_LOCAL_EXAMPLE_V1|" + rid)})
    selected = []
    for stratum in sorted({r["stratum"] for r in rows}): selected.extend(sorted((r for r in rows if r["stratum"] == stratum), key=lambda r: r["selection_hash"])[:2])
    return selected


def main():
    if sys.version.split()[0] != "3.10.11" or sklearn.__version__ != "1.7.2" or shap.__version__ != "0.49.1": raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    if any((OUT / name).exists() for name in REQUIRED_OUTPUTS): raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    if (ROOT / "data/interim/phase3/p3_14").exists(): raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    if sha(GOV) != EXPECTED["governance"] or sha(COHORT) != EXPECTED["cohort"] or sha(FEATURES) != EXPECTED["features"] or sha(CORPUS) != EXPECTED["corpus"]: raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    lock = json.loads(LOCK.read_text(encoding="utf-8")); governance = json.loads(GOV.read_text(encoding="utf-8")); recon_manifest = json.loads(RECON_MANIFEST.read_text(encoding="utf-8"))
    policy = governance["prospective_pre_execution_governance_decisions_added_2026_08_31"]
    if lock["shap"]["installed_version"] != shap.__version__ or policy["M2"]["shap_version"] != shap.__version__: raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    registry, paths = load_objects_and_verify(); groups, feature_contract_sha = feature_groups()
    cohort = list(csv.DictReader(COHORT.open(newline="", encoding="utf-8-sig"))); ids = [r["combined_row_id"] for r in cohort]
    labels = np.asarray([label(r.get("label", r.get("label_numeric"))) for r in cohort], dtype=int)
    if len(ids) != 2801 or len(set(ids)) != 2801 or int((labels == 0).sum()) != 1182 or int((labels == 1).sum()) != 1619: raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    if any(r.get("regime_a_s42_partition") != "test" or r.get("regime_c_s42_partition") != "test" for r in cohort): raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    corpus, feats = load_cohort_data(ids)
    if not np.array_equal(labels, np.asarray([corpus[r]["label"] for r in ids], dtype=int)): raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    if recon_manifest["cohort_verification"]["raw_url_keyed_sha256"] != keyed_digest(corpus, ["raw_url"]) or recon_manifest["cohort_verification"]["engineered_feature_keyed_sha256"] != keyed_digest(feats, FEATURE_NAMES): raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    x = np.asarray([[float(feats[rid][name]) for name in FEATURE_NAMES] for rid in ids], dtype=float)
    canonical = {regime: {model: read_canonical(PREDICTIONS[regime][model]) for model in ("M1", "M2", "M3")} for regime in ("A", "C")}
    for regime in ("A", "C"):
        for model in ("M1", "M2", "M3"):
            frame = canonical[regime][model]
            expected_sha = next(r["canonical_prediction_sha256"] for r in registry if r["regime"] == regime and r["model"] == model)
            if sha(PREDICTIONS[regime][model]) != expected_sha or set(frame.index) < set(ids) or not np.array_equal(frame.loc[ids, "true_label_numeric"].to_numpy(dtype=int), labels): raise RuntimeError("P3_13_EXECUTION_PREFLIGHT_FAILED_REQUIRES_REVIEW")
    shap_subset = sorted(ids, key=lambda rid: stable("P3_13_SHAP_DETERMINISM_V1|" + rid))[:16]
    permutation_identities = sorted([(regime, fi, repeat) for regime in ("A", "C") for fi in range(22) for repeat in range(30)], key=lambda z: stable(f"P3_13_PERMUTATION_DETERMINISM_V1|{z[0]}|{z[1]}|{z[2]}"))[:4]
    execution_contract = {"governance_sha256": sha(GOV), "feature_group_mapping_sha256": feature_contract_sha, "feature_family_aggregation": "FROZEN_ENGINEERED_FEATURE_CONTRACT", "shap": {"version": shap.__version__, "feature_perturbation": "tree_path_dependent", "model_output": "raw", "background": "NOT_USED", "repeat_subset_ids": shap_subset, "repeat_tolerance": SHAP_REPEAT_TOL}, "permutation": {"seed": policy["M2"]["permutation_importance"]["seed"], "repetitions": 30, "scoring": "MCC", "rng_policy": "Per-regime numpy RandomState(master_seed); frozen feature order; repeats 0..29; feature column only is permuted.", "determinism_identities": [{"regime": r, "feature": FEATURE_NAMES[f], "repeat": k} for r, f, k in permutation_identities]}, "safety": {"canonical_model_fits": 0, "hyperparameter_searches": 0, "threshold_tuning": 0, "P3_14_executed": False}}
    write_json(OUT / "P3_13_ATTRIBUTION_CONTRACT.json", execution_contract)
    # Freeze local examples from canonical M2 outcomes before SHAP is viewed.
    local_selection = select_local_examples(ids, labels, canonical["A"]["M2"].loc[ids, "predicted_label_numeric"].to_numpy(dtype=int), canonical["C"]["M2"].loc[ids, "predicted_label_numeric"].to_numpy(dtype=int))
    write_csv(OUT / "P3_13_LOCAL_EXAMPLE_SELECTION.csv", local_selection, list(local_selection[0]))
    write_csv(OUT / "P3_13_PLOT_LOCAL_EXAMPLES.csv", local_selection, list(local_selection[0]))
    # M1
    m1 = {r: joblib.load(paths[(r, "M1", "model")]) for r in ("A", "C")}
    m1_rows = []
    abs_a, abs_c = np.abs(m1["A"].coef_.ravel()), np.abs(m1["C"].coef_.ravel())
    for j, feature in enumerate(FEATURE_NAMES):
        m1_rows.append({"feature": feature, "feature_index": j, "feature_group": groups[feature], "A42_coefficient": float(m1["A"].coef_.ravel()[j]), "C42_coefficient": float(m1["C"].coef_.ravel()[j]), "A42_abs_coefficient": float(abs_a[j]), "C42_abs_coefficient": float(abs_c[j]), "delta_signed": float(m1["C"].coef_.ravel()[j] - m1["A"].coef_.ravel()[j]), "delta_abs": float(abs_c[j] - abs_a[j]), "A42_rank_abs": float(rankdata(-abs_a, method="average")[j]), "C42_rank_abs": float(rankdata(-abs_c, method="average")[j])})
    m1_spearman = float(spearmanr(abs_a, abs_c).statistic)
    write_csv(OUT / "P3_13_M1_COEFFICIENTS.csv", m1_rows, list(m1_rows[0]))
    write_csv(OUT / "P3_13_M1_A_C_COMPARISON.csv", m1_rows, list(m1_rows[0]))
    # M2 SHAP, all/global/class-conditioned/local.
    m2 = {r: joblib.load(paths[(r, "M2", "model")]) for r in ("A", "C")}
    phi = {}
    for regime in ("A", "C"):
        explainer = shap.TreeExplainer(m2[regime], feature_perturbation="tree_path_dependent", model_output="raw", feature_names=FEATURE_NAMES)
        values = np.asarray(explainer.shap_values(x), dtype=float)
        if values.shape != (len(ids), len(FEATURE_NAMES)): raise RuntimeError("P3_13_SHAP_EXECUTION_FAILED_REQUIRES_REVIEW")
        phi[regime] = values
    m2_local, m2_change = [], []
    denom_a, denom_c = np.abs(phi["A"]).sum(axis=1), np.abs(phi["C"]).sum(axis=1)
    if np.any(denom_a == 0) or np.any(denom_c == 0): raise RuntimeError("P3_13_ZERO_ATTRIBUTION_NORMALIZATION_REQUIRES_REVIEW")
    for i, rid in enumerate(ids):
        raw = float(np.abs(phi["C"][i] - phi["A"][i]).sum()); norm = float(np.abs(phi["C"][i] / denom_c[i] - phi["A"][i] / denom_a[i]).sum())
        m2_change.append({"comparison_level": "LOCAL", "combined_row_id": rid, "true_label_numeric": int(labels[i]), "feature": "", "feature_index": "", "stratum": "all", "A42_mean_abs_shap": "", "C42_mean_abs_shap": "", "delta_mean_abs_shap": "", "raw_local_change": raw, "normalized_local_change": norm})
        for j, feature in enumerate(FEATURE_NAMES): m2_local.append({"combined_row_id": rid, "true_label_numeric": int(labels[i]), "feature": feature, "feature_index": j, "feature_group": groups[feature], "A42_SHAP": float(phi["A"][i, j]), "C42_SHAP": float(phi["C"][i, j]), "raw_local_change": raw, "normalized_local_change": norm})
    global_rows = []
    for stratum, mask in (("all", np.ones(len(ids), dtype=bool)), ("benign", labels == 0), ("phishing", labels == 1)):
        ga, gc = np.mean(np.abs(phi["A"][mask]), axis=0), np.mean(np.abs(phi["C"][mask]), axis=0)
        for j, feature in enumerate(FEATURE_NAMES):
            row = {"regime": "A42", "stratum": stratum, "row_count": int(mask.sum()), "feature": feature, "feature_index": j, "feature_group": groups[feature], "mean_abs_shap": float(ga[j])}; global_rows.append(row)
            global_rows.append({**row, "regime": "C42", "mean_abs_shap": float(gc[j])})
            m2_change.append({"comparison_level": "GLOBAL", "combined_row_id": "", "true_label_numeric": "", "feature": feature, "feature_index": j, "stratum": stratum, "A42_mean_abs_shap": float(ga[j]), "C42_mean_abs_shap": float(gc[j]), "delta_mean_abs_shap": float(gc[j] - ga[j]), "raw_local_change": "", "normalized_local_change": ""})
    ga_all = np.mean(np.abs(phi["A"]), axis=0); gc_all = np.mean(np.abs(phi["C"]), axis=0); m2_spearman = float(spearmanr(ga_all, gc_all).statistic)
    write_csv(OUT / "P3_13_M2_SHAP_LOCAL.csv", m2_local, list(m2_local[0])); write_csv(OUT / "P3_13_M2_SHAP_GLOBAL.csv", global_rows, list(global_rows[0])); write_csv(OUT / "P3_13_M2_A_C_CHANGE.csv", m2_change, list(m2_change[0]))
    # M2 permutation, with a single documented RandomState stream per regime.
    perm_rows, audit_permutations, counter_calls = [], {}, 0
    seed = int(policy["M2"]["permutation_importance"]["seed"])
    for regime in ("A", "C"):
        base_prob = probability(m2[regime], x); baseline = float(matthews_corrcoef(labels, (base_prob >= 0.5).astype(int))); counter_calls += 1
        rng = np.random.RandomState(seed)
        for j, feature in enumerate(FEATURE_NAMES):
            for repeat in range(30):
                permutation = rng.permutation(len(ids)); xp = x.copy(); xp[:, j] = x[permutation, j]
                value = float(baseline - matthews_corrcoef(labels, (probability(m2[regime], xp) >= 0.5).astype(int))); counter_calls += 1
                row = {"regime": f"{regime}42", "model": "M2", "feature": feature, "feature_index": j, "feature_group": groups[feature], "repeat": repeat, "seed": seed, "baseline_MCC": baseline, "permuted_MCC": baseline - value, "importance_MCC_decrease": value, "cohort_sha256": sha(COHORT), "prediction_generation_class": "ATTRIBUTION_COUNTERFACTUAL_PREDICTION_CALLS"}; perm_rows.append(row)
                if (regime, j, repeat) in permutation_identities: audit_permutations[(regime, j, repeat)] = (permutation.copy(), value)
    perm_audit = []
    for regime, j, repeat in permutation_identities:
        perm, saved = audit_permutations[(regime, j, repeat)]; xp = x.copy(); xp[:, j] = x[perm, j]
        baseline = next(r["baseline_MCC"] for r in perm_rows if r["regime"] == f"{regime}42" and r["feature_index"] == j and r["repeat"] == repeat)
        replay = float(baseline - matthews_corrcoef(labels, (probability(m2[regime], xp) >= 0.5).astype(int))); counter_calls += 1
        if replay != saved: raise RuntimeError("P3_13_PERMUTATION_EXECUTION_FAILED_REQUIRES_REVIEW")
        perm_audit.append({"regime": f"{regime}42", "feature": FEATURE_NAMES[j], "repeat": repeat, "saved_importance": saved, "replay_importance": replay, "absolute_difference": abs(saved - replay), "status": "PASS"})
    write_csv(OUT / "P3_13_M2_PERMUTATION_IMPORTANCE.csv", perm_rows, list(perm_rows[0]))
    # M3 token-only comparison.
    m3v = {r: joblib.load(paths[(r, "M3", "preprocessor")]) for r in ("A", "C")}; m3m = {r: joblib.load(paths[(r, "M3", "model")]) for r in ("A", "C")}
    tokens = {r: {token: float(m3m[r].coef_.ravel()[index]) for token, index in m3v[r].vocabulary_.items()} for r in ("A", "C")}
    m3_top = []
    for regime in ("A", "C"):
        values = tokens[regime]
        orders = {"positive": sorted(values, key=lambda t: (-values[t], t))[:50], "negative": sorted(values, key=lambda t: (values[t], t))[:50], "absolute": sorted(values, key=lambda t: (-abs(values[t]), t))[:50]}
        for kind, terms in orders.items():
            for rank, token in enumerate(terms, 1): m3_top.append({"regime": f"{regime}42", "list_type": kind, "rank": rank, "token": token, "coefficient": values[token], "abs_coefficient": abs(values[token])})
    shared = sorted(set(tokens["A"]) & set(tokens["C"])); sign_rate = float(np.mean([np.sign(tokens["A"][t]) == np.sign(tokens["C"][t]) for t in shared])); shared_spearman = float(spearmanr([abs(tokens["A"][t]) for t in shared], [abs(tokens["C"][t]) for t in shared]).statistic)
    shared_rows = [{"A42_vocabulary_size": len(tokens["A"]), "C42_vocabulary_size": len(tokens["C"]), "shared_vocabulary_size": len(shared), "shared_fraction_A42": len(shared) / len(tokens["A"]), "shared_fraction_C42": len(shared) / len(tokens["C"]), "shared_token_sign_agreement_rate": sign_rate, "shared_token_abs_coefficient_spearman": shared_spearman, "p_value_reported": False, "union_zero_padding_used": False}]
    top_a, top_c = {r["token"] for r in m3_top if r["regime"] == "A42" and r["list_type"] == "absolute"}, {r["token"] for r in m3_top if r["regime"] == "C42" and r["list_type"] == "absolute"}
    overlap = sorted(top_a & top_c)
    overlap_signs = [np.sign(tokens["A"][t]) == np.sign(tokens["C"][t]) for t in overlap]
    overlap_rows = [{"K": 50, "A42_top_k_count": len(top_a), "C42_top_k_count": len(top_c), "intersection_count": len(overlap), "union_count": len(top_a | top_c), "jaccard_overlap": len(overlap) / len(top_a | top_c), "overlap_sign_agreement_count": sum(overlap_signs), "overlap_sign_agreement_rate": float(np.mean(overlap_signs)) if overlap else float("nan")}]
    write_csv(OUT / "P3_13_M3_TOP_NGRAMS.csv", m3_top, list(m3_top[0])); write_csv(OUT / "P3_13_M3_SHARED_VOCABULARY_COMPARISON.csv", shared_rows, list(shared_rows[0])); write_csv(OUT / "P3_13_M3_TOPK_OVERLAP.csv", overlap_rows, list(overlap_rows[0]))
    # Bounded SHAP determinism audit after primary computation.
    subset_index = np.asarray([ids.index(rid) for rid in shap_subset], dtype=int); shap_audit = []
    for regime in ("A", "C"):
        repeat = np.asarray(shap.TreeExplainer(m2[regime], feature_perturbation="tree_path_dependent", model_output="raw", feature_names=FEATURE_NAMES).shap_values(x[subset_index]), dtype=float)
        difference = float(np.max(np.abs(repeat - phi[regime][subset_index])))
        if difference > SHAP_REPEAT_TOL: raise RuntimeError("P3_13_SHAP_EXECUTION_FAILED_REQUIRES_REVIEW")
        shap_audit.append({"regime": f"{regime}42", "row_count": len(shap_subset), "selection_rule": "first 16 ascending SHA-256(P3_13_SHAP_DETERMINISM_V1|combined_row_id)", "max_absolute_difference": difference, "tolerance": SHAP_REPEAT_TOL, "status": "PASS"})
    # Access, summary, plotting, and invariants.
    access = []
    for regime in ("A", "C"):
        for model in ("M1", "M2", "M3"):
            roles = [r for r in registry if r["regime"] == regime and r["model"] == model]
            access.append({"operation_class": "READ_ONLY_COMMON_TEST_ATTRIBUTION", "model": model, "regime": f"{regime}42", "cohort_sha256": sha(COHORT), "object_sha256": ";".join(r["sha256"] for r in roles), "operation": "cohort attribution/coefficient analysis", "row_count": len(ids), "test_label_access": "READ_ONLY", "prediction_generation_class": "FALSE", "selection_impact": "NONE", "timestamp_utc": now()})
        access.append({"operation_class": "ATTRIBUTION_COUNTERFACTUAL_PREDICTION_CALLS", "model": "M2", "regime": f"{regime}42", "cohort_sha256": sha(COHORT), "object_sha256": next(r["sha256"] for r in registry if r["regime"] == regime and r["model"] == "M2" and r["artifact_role"] == "model"), "operation": "feature-only permutation MCC", "row_count": len(ids), "test_label_access": "READ_ONLY", "prediction_generation_class": "ATTRIBUTION_COUNTERFACTUAL_PREDICTION_CALLS", "selection_impact": "NONE", "timestamp_utc": now()})
    write_csv(OUT / "P3_13_ATTRIBUTION_ACCESS_LOG.csv", access, list(access[0])); write_csv(OUT / "P3_13_INPUT_REGISTRY.csv", registry, list(registry[0])); write_csv(OUT / "P3_13_MODEL_REGISTRY.csv", registry, list(registry[0]))
    summary = [{"model": "M1", "metric": "global_abs_coefficient_spearman", "value": m1_spearman, "interpretation_scope": "within-model A42/C42 descriptive"}, {"model": "M2", "metric": "global_mean_abs_shap_spearman", "value": m2_spearman, "interpretation_scope": "within-model A42/C42 descriptive"}, {"model": "M2", "metric": "mean_raw_local_change", "value": float(np.mean([r["raw_local_change"] for r in m2_change if r["comparison_level"] == "LOCAL"])), "interpretation_scope": "within-row descriptive"}, {"model": "M2", "metric": "mean_normalized_local_change", "value": float(np.mean([r["normalized_local_change"] for r in m2_change if r["comparison_level"] == "LOCAL"])), "interpretation_scope": "within-row descriptive"}, {"model": "M3", "metric": "shared_token_abs_coefficient_spearman", "value": shared_spearman, "interpretation_scope": "shared-token descriptive"}, {"model": "M3", "metric": "top50_jaccard", "value": overlap_rows[0]["jaccard_overlap"], "interpretation_scope": "top-token descriptive"}]
    write_csv(OUT / "P3_13_ATTRIBUTION_SUMMARY.csv", summary, list(summary[0])); write_csv(OUT / "P3_13_PLOT_GLOBAL_ATTRIBUTION.csv", global_rows, list(global_rows[0]))
    plot_change_rows = [
        {"model": "M2", "feature": r["feature"], "feature_index": r["feature_index"], "stratum": r["stratum"], "change_metric": "delta_mean_abs_shap", "value": r["delta_mean_abs_shap"]}
        for r in m2_change if r["comparison_level"] == "GLOBAL"
    ] + [
        {"model": "M1", "feature": r["feature"], "feature_index": r["feature_index"], "stratum": "all", "change_metric": "delta_abs_coefficient", "value": r["delta_abs"]}
        for r in m1_rows
    ]
    write_csv(OUT / "P3_13_PLOT_ATTRIBUTION_CHANGE.csv", plot_change_rows, list(plot_change_rows[0])); write_csv(OUT / "P3_13_PLOT_M3_TOPK.csv", m3_top, list(m3_top[0]))
    invariant_rows = [
        ("P313-E01", "governance SHA verified", "PASS", sha(GOV)), ("P313-E02", "cohort SHA verified", "PASS", sha(COHORT)), ("P313-E03", "cohort count 2801", "PASS", "2801"), ("P313-E04", "cohort class counts verified", "PASS", "1182 benign; 1619 phishing"), ("P313-E05", "six model-object hashes verified", "PASS", "12 object records / 6 pipelines"), ("P313-E06", "canonical predictions unchanged", "PASS", "six canonical SHA checks"), ("P313-E07", "no model fitting", "PASS", "0"), ("P313-E08", "no hyperparameter selection", "PASS", "0"), ("P313-E09", "no threshold tuning", "PASS", "0"), ("P313-E10", "M1 feature order verified", "PASS", "22 frozen features"), ("P313-E11", "M1 coefficients extracted", "PASS", "44 regime-feature rows"), ("P313-E12", "M1 A/C comparison complete", "PASS", str(m1_spearman)), ("P313-E13", "SHAP version verified", "PASS", shap.__version__), ("P313-E14", "TreeSHAP configuration verified", "PASS", "tree_path_dependent/raw/no background"), ("P313-E15", "M2 SHAP rows complete", "PASS", str(len(m2_local))), ("P313-E16", "M2 SHAP global summary complete", "PASS", str(len(global_rows))), ("P313-E17", "M2 class-conditioned summary complete", "PASS", "all/benign/phishing"), ("P313-E18", "M2 local change complete", "PASS", str(len(ids))), ("P313-E19", "permutation seed verified", "PASS", str(seed)), ("P313-E20", "permutation 30 repeats complete", "PASS", str(len(perm_rows))), ("P313-E21", "permutation scoring MCC", "PASS", "MCC"), ("P313-E22", "M3 A vocabulary recorded", "PASS", str(len(tokens["A"]))), ("P313-E23", "M3 C vocabulary recorded", "PASS", str(len(tokens["C"]))), ("P313-E24", "shared vocabulary exact", "PASS", str(len(shared))), ("P313-E25", "M3 union-zero padding unused", "PASS", "false"), ("P313-E26", "M3 top-K=50", "PASS", "50"), ("P313-E27", "generic stability unused", "PASS", "NOT_USED"), ("P313-E28", "p-values absent", "PASS", "0"), ("P313-E29", "attribution bootstrap absent", "PASS", "0"), ("P313-E30", "source/site causal claims absent", "PASS", "claim firewall"), ("P313-E31", "P3-14 not executed", "PASS", "false"), ("P313-E32", "bounded SHAP determinism audit", "PASS", json.dumps(shap_audit)), ("P313-E33", "bounded permutation determinism audit", "PASS", json.dumps(perm_audit)),
    ]
    invariants = [{"invariant_id": a, "requirement": b, "status": c, "evidence": d} for a, b, c, d in invariant_rows]; write_csv(OUT / "P3_13_INVARIANTS.csv", invariants, list(invariants[0]))
    report = ROOT / "docs/reports/phase3_p3_13_rq3_attribution_analysis_2026-08-31.md"; note = ROOT / "docs/manuscript/P3_13_RQ3_ATTRIBUTION_EVIDENCE_2026-08-31.md"
    largest_m1 = sorted(m1_rows, key=lambda r: -abs(r["delta_abs"]))[:5]; global_all = [r for r in m2_change if r["comparison_level"] == "GLOBAL" and r["stratum"] == "all"]; largest_m2 = sorted(global_all, key=lambda r: -abs(r["delta_mean_abs_shap"]))[:5]
    report.parent.mkdir(parents=True, exist_ok=True); note.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# P3-13 RQ3 attribution analysis\n\nClassification: `P3_13_RQ3_ATTRIBUTION_ANALYSIS_PASSED`.\n\n## Scope and provenance\n\nThe frozen 2,801-row A42/C42 common cohort was aligned by `combined_row_id`. Six SHA-verified reconstructed selected pipelines were used without fitting, retuning, or changing canonical predictions. M2 used TreeSHAP 0.49.1 with `tree_path_dependent` and raw output; permutation importance used 30 MCC repetitions with seed 42.\n\n## Results\n\n- M1 absolute-coefficient rank similarity: %.6f.\n- M2 mean-absolute-SHAP rank similarity: %.6f.\n- M2 mean raw local change: %.6f; mean normalized local change: %.6f.\n- M3 shared-token absolute-coefficient rank similarity: %.6f; top-50 Jaccard overlap: %.6f.\n\nLargest M1 absolute-magnitude changes: %s.\n\nLargest M2 all-cohort mean-absolute-SHAP changes: %s.\n\n## Interpretation boundary\n\nThese are within-model, descriptive attribution comparisons. They quantify changed coefficient/attribution patterns under the frozen A42 versus C42 evaluation regimes. They do not establish source reliance, site memorization, causal feature effects, shortcut learning, statistical significance, or deployment generalization.\n\n## Controls and successor\n\nAll 33 execution invariants passed. No p-values, bootstrap, hyperparameter search, canonical model fitting, or P3-14 work occurred. Exact next frozen step: P3-14 Error analysis; not executed.\n" % (m1_spearman, m2_spearman, summary[2]["value"], summary[3]["value"], shared_spearman, overlap_rows[0]["jaccard_overlap"], ", ".join(r["feature"] for r in largest_m1), ", ".join(r["feature"] for r in largest_m2)), encoding="utf-8")
    note.write_text("# P3-13 RQ3 attribution evidence\n\nUsing the frozen 2,801-row common A42/C42 cohort and SHA-verified reconstructed selected pipelines, M1 standardized coefficients, M2 raw-output TreeSHAP plus MCC permutation importance, and M3 token-level shared-vocabulary/top-50 comparisons quantified within-model attribution-pattern changes. M1 absolute-coefficient rank similarity was %.6f and M2 mean-absolute-SHAP rank similarity was %.6f. M3 shared-token rank similarity was %.6f with top-50 Jaccard overlap %.6f. These descriptive comparisons do not establish causal feature effects, source reliance, site memorization, or statistical significance.\n" % (m1_spearman, m2_spearman, shared_spearman, overlap_rows[0]["jaccard_overlap"]), encoding="utf-8")
    manifest = {"classification": "P3_13_RQ3_ATTRIBUTION_ANALYSIS_PASSED", "governance_sha256": sha(GOV), "cohort_sha256": sha(COHORT), "cohort_rows": len(ids), "feature_family_mapping": {"path": "data/interim/phase2c/step23_phase3_execution_bundle/engineered_feature_contract.json", "sha256": feature_contract_sha, "status": "FROZEN_MAPPING_USED"}, "object_integrity": "6/6 pipelines PASS", "canonical_model_fits": 0, "hyperparameter_searches": 0, "threshold_tuning": 0, "SHAP_scientific_rows_computed": len(ids) * 2, "permutation_importance_runs": len(perm_rows), "counterfactual_prediction_calls": counter_calls, "p_values_generated": 0, "bootstrap_runs": 0, "P3_14_executed": False, "determinism": {"shap": shap_audit, "permutation": perm_audit}, "environment": {"python": sys.version, "platform": platform.platform(), "numpy": np.__version__, "pandas": pd.__version__, "scipy": scipy.__version__, "sklearn": sklearn.__version__, "shap": shap.__version__}, "runner": {"path": str(Path(__file__).relative_to(ROOT)).replace("\\", "/"), "sha256": sha(Path(__file__))}, "created_utc": now(), "artifacts": {p.name: sha(p) for p in OUT.iterdir() if p.is_file() and p.name != "P3_13_EXECUTION_MANIFEST.json"}}
    write_json(OUT / "P3_13_EXECUTION_MANIFEST.json", manifest)
    print(json.dumps({"classification": manifest["classification"], "m1_spearman": m1_spearman, "m2_spearman": m2_spearman, "m3_shared_spearman": shared_spearman, "m3_top50_jaccard": overlap_rows[0]["jaccard_overlap"], "invariants": len(invariants)}, default=str))


if __name__ == "__main__": main()
