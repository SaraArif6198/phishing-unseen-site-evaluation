from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


ROOT = Path(__file__).resolve().parent
PARSED = ROOT / "data_phase2/outputs/legitphish/parsed_urls.parquet"
OUT = ROOT / "data_phase2/outputs/legitphish/splits"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [13, 42, 73, 101, 2026]


def assign(frame: pd.DataFrame, group_col: str, seed: int) -> pd.Series:
    def best_group_holdout(data: pd.DataFrame, fraction: float, local_seed: int):
        splitter = GroupShuffleSplit(n_splits=40, test_size=fraction, random_state=local_seed)
        target = data.groupby("ClassLabel").size() * fraction
        best = None
        best_score = float("inf")
        for keep, hold in splitter.split(data, groups=data[group_col]):
            held = data.iloc[hold].groupby("ClassLabel").size().reindex(target.index, fill_value=0)
            score = float((((held - target) / target.clip(lower=1)) ** 2).sum())
            if score < best_score:
                best_score, best = score, (keep, hold)
        return best

    split = pd.Series(index=frame.index, dtype="object")
    keep_idx, test_idx = best_group_holdout(frame, .15, seed)
    split.loc[frame.index[test_idx]] = "test"
    remain = frame.iloc[keep_idx]
    train_rel, val_rel = best_group_holdout(remain, .15 / .85, seed + 10000)
    split.loc[remain.index[train_rel]] = "train"
    split.loc[remain.index[val_rel]] = "validation"
    assert split.notna().all()
    return split


def validate(frame: pd.DataFrame, group_col: str, split: pd.Series) -> dict:
    result = {"group_key": group_col}
    for part in ["train", "validation", "test"]:
        z = frame[split == part]
        result[part] = {
            "rows": int(len(z)),
            "phishing_rows": int((z.ClassLabel == 0.0).sum()),
            "benign_rows": int((z.ClassLabel == 1.0).sum()),
            "groups": int(z[group_col].nunique()),
            "phishing_sites": int(z.loc[z.ClassLabel == 0.0, "site_key_private"].nunique()),
            "benign_sites": int(z.loc[z.ClassLabel == 1.0, "site_key_private"].nunique()),
        }
    sets = {p: set(frame.loc[split == p, group_col]) for p in ["train", "validation", "test"]}
    result["overlaps"] = {
        "train_validation": len(sets["train"] & sets["validation"]),
        "train_test": len(sets["train"] & sets["test"]),
        "validation_test": len(sets["validation"] & sets["test"]),
    }
    result["all_rows_assigned_once"] = bool(split.notna().all() and len(split) == len(frame))
    if group_col == "hostname_ascii":
        site_sets = {p: set(frame.loc[split == p, "site_key_private"]) for p in sets}
        result["psl_site_overlap_despite_hostname_disjointness"] = {
            "train_validation": len(site_sets["train"] & site_sets["validation"]),
            "train_test": len(site_sets["train"] & site_sets["test"]),
            "validation_test": len(site_sets["validation"] & site_sets["test"]),
        }
    return result


def main() -> None:
    x = pd.read_parquet(PARSED)
    x = x[x.ClassLabel.isin([0.0, 1.0])].copy()
    summaries = []
    for group_col, regime in [
        ("hostname_ascii", "hostname_disjoint"),
        ("site_key_icann", "site_disjoint_icann"),
        ("site_key_private", "site_disjoint_private"),
    ]:
        frame = x[x[group_col].fillna("").ne("")].copy()
        for seed in SEEDS:
            split = assign(frame, group_col, seed)
            manifest = frame[["row_id", "ClassLabel", "hostname_ascii", "site_key_icann", "site_key_private"]].copy()
            manifest["split"] = split
            manifest.to_parquet(OUT / f"candidate_{regime}_seed{seed}.parquet", index=False)
            summary = validate(frame, group_col, split)
            summary.update({"regime": regime, "seed": seed})
            summaries.append(summary)
    (OUT / "split_summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    flat = []
    for s in summaries:
        for part in ["train", "validation", "test"]:
            flat.append({"regime": s["regime"], "seed": s["seed"], "partition": part, **s[part], **{f"overlap_{k}": v for k, v in s["overlaps"].items()}})
    pd.DataFrame(flat).to_csv(OUT / "split_summary.csv", index=False)
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
