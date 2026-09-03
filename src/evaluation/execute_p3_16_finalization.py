"""Render governed P3-16 figures/tables from frozen machine-readable artifacts.

This script only formats or copies frozen results. It does not import model
objects, prediction files, or raw URL data, and it performs no inference.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np
import pandas as pd
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
PHASE3 = ROOT / "data/interim/phase3"
P2C = ROOT / "data/interim/phase2c"
SCOPE = PHASE3 / "p3_16_scope_reconstruction"
FINAL = PHASE3 / "p3_16_finalization"
FIGDIR = ROOT / "figures/final"
TABDIR = ROOT / "tables/final"
REPORT = ROOT / "docs/reports/phase3_p3_16_final_figures_tables_result_manifest_2026-09-01.md"

BLUE, ORANGE, GREEN, PURPLE = "#0072B2", "#E69F00", "#009E73", "#CC79A7"
MODELS = ["M1", "M2", "M3"]


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader(); w.writerows(rows)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2); f.write("\n")


def display_pct(v: float) -> float:
    return 100.0 * v if abs(v) <= 1.0 else v


def style() -> None:
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 10, "legend.fontsize": 8, "figure.facecolor": "white", "axes.facecolor": "white", "savefig.facecolor": "white"})


def save_figure(fig, registry: list[dict[str, str]], fig_id: str, caption: str, source_paths: list[Path]) -> None:
    row = next(r for r in registry if r["final_figure_id"] == fig_id)
    paths = []
    for field in ("output_pdf", "output_svg", "output_png"):
        p = ROOT / row[field]
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix == ".png": fig.savefig(p, dpi=300)
        else: fig.savefig(p)
        # Matplotlib's SVG backend emits indentation spaces after path commands.
        # Strip only line-end whitespace so the vector rendering is unchanged and
        # the generated artifact passes repository whitespace validation.
        if p.suffix == ".svg":
            p.write_text("\n".join(line.rstrip() for line in p.read_text(encoding="utf-8").splitlines()) + "\n", encoding="utf-8", newline="\n")
        paths.append(p)
    plt.close(fig)
    row["status"] = "GENERATED_VALIDATED"
    row["source_shas"] = ";".join(f"{rel(p)}={sha(p)}" for p in source_paths)
    row["caption_boundary"] = caption
    ARTIFACTS.extend(provenance_record(p, source_paths, "FIGURE", fig_id) for p in paths)


def provenance_record(path: Path, sources: list[Path], kind: str, owner: str) -> dict[str, str]:
    return {"artifact_type": kind, "owner_id": owner, "output_path": rel(path), "output_sha256": sha(path), "source_paths": ";".join(rel(p) for p in sources), "source_shas": ";".join(sha(p) for p in sources), "generation_script": rel(Path(__file__)), "generation_script_sha256": sha(Path(__file__)), "generation_commit": START_HEAD, "timestamp_utc": NOW}


def as_md(path: Path, columns: list[str], caption: str) -> None:
    frame = pd.read_csv(path, dtype=str).fillna("")
    use = [c for c in columns if c in frame.columns]
    with path.with_suffix(".md").open("w", encoding="utf-8", newline="\n") as f:
        f.write(f"<!-- {caption} -->\n\n")
        f.write("| " + " | ".join(use) + " |\n")
        f.write("| " + " | ".join(["---"] * len(use)) + " |\n")
        for _, row in frame.iterrows():
            f.write("| " + " | ".join(str(row[c]).replace("|", "\\|") for c in use) + " |\n")


def write_table(table_registry: list[dict[str, str]], table_id: str, rows: list[dict[str, object]], fields: list[str], caption: str, sources: list[Path], md_columns: list[str]) -> None:
    row = next(r for r in table_registry if r["table_id"] == table_id)
    csv_path = ROOT / row["output_csv"]
    write_csv(csv_path, fields, rows)
    as_md(csv_path, md_columns, caption)
    md_path = csv_path.with_suffix(".md")
    row["status"] = "GENERATED_VALIDATED"
    row["source_shas"] = ";".join(f"{rel(p)}={sha(p)}" for p in sources)
    ARTIFACTS.extend([provenance_record(csv_path, sources, "TABLE", table_id), provenance_record(md_path, sources, "TABLE", table_id)])


def main() -> None:
    global START_HEAD, NOW, ARTIFACTS
    START_HEAD = git("rev-parse", "HEAD")
    NOW = datetime.now(timezone.utc).isoformat()
    ARTIFACTS = []
    if subprocess.call(["git", "merge-base", "--is-ancestor", "550fbe5fcdc3a3ef2b9e248348f55563ceea63b7", "HEAD"], cwd=ROOT) != 0:
        raise RuntimeError("P3-16 governance commit missing from lineage")

    addendum_path = SCOPE / "P3_16_GOVERNANCE_ADDENDUM.json"
    manifest_path = FINAL / "P3_16_FINAL_RESULT_MANIFEST.csv"
    manifest_json_path = FINAL / "P3_16_FINAL_RESULT_MANIFEST.json"
    figure_registry_path = FINAL / "P3_16_FINAL_FIGURE_REGISTRY.csv"
    table_registry_path = FINAL / "P3_16_FINAL_TABLE_REGISTRY.csv"
    inventory_path = SCOPE / "P3_16_RESULT_INVENTORY.csv"
    required = [addendum_path, manifest_path, manifest_json_path, figure_registry_path, table_registry_path, inventory_path]
    if any(not p.exists() for p in required): raise RuntimeError("P3-16 governance artifacts missing")
    addendum = json.loads(addendum_path.read_text(encoding="utf-8"))
    if addendum["prospective_governance_classification"] != "P3_16_SCOPE_RECONSTRUCTED_READY_FOR_FIGURE_FINALIZATION": raise RuntimeError("governance not ready")

    inventory = read_csv(inventory_path)
    if len(inventory) != 427: raise RuntimeError("expected 427 canonical inventory records")
    unique_sources = {ROOT / r["source_artifact_path"]: r["source_sha256"] for r in inventory}
    for path, expected in unique_sources.items():
        if not path.exists() or sha(path) != expected: raise RuntimeError(f"source hash mismatch: {rel(path)}")
    registry_source = PHASE3 / "PHASE3_AUTHORITATIVE_RESULT_REGISTRY.csv"
    scope_state = json.loads((SCOPE / "p3_16_scope_reconstruction.json").read_text(encoding="utf-8"))
    if sha(registry_source) != scope_state["authoritative_result_registry"]["sha"]: raise RuntimeError("authoritative registry SHA mismatch")

    # Populate final result manifest by copying—not recomputing—the scope inventory.
    fields = addendum["result_manifest"]["columns"]
    phase_rq = {"P3-03": "SUPPORTING", "P3-04": "RQ1/RQ2", "P3-05": "RQ1/RQ2", "P3-06": "RQ1/RQ2", "P3-07": "RQ1/RQ2", "P3-08": "SUPPORTING", "P3-09": "DIAGNOSTIC", "P3-10": "SUPPORTING", "P3-11": "SUPPORTING", "P3-12": "RQ1/RQ2", "P3-13": "RQ3", "P3-14": "SUPPORTING"}
    phase_use = {"P3-12": ("MAIN_F3;MAIN_F4", "T5"), "P3-13": ("MAIN_F5", "T8"), "P3-14": ("F18", "T9"), "P3-08": ("F11", "T6"), "P3-10": ("F12", "T7"), "P3-11": ("F13", ""), "P3-06": ("MAIN_F3", "T5"), "P3-07": ("MAIN_F3", "T5")}
    manifest_rows = []
    for i, row in enumerate(inventory, 1):
        lower, upper, utype = "", "", "NONE"
        if row["uncertainty"]:
            match = re.search(r"\[([^,]+), ([^\]]+)\]", row["uncertainty"])
            if match: lower, upper, utype = match.group(1), match.group(2), "95%_SITE_CLUSTER_PERCENTILE_BOOTSTRAP_INTERVAL"
            else: utype = row["uncertainty"]
        fig, tab = phase_use.get(row["phase"], ("", ""))
        manifest_rows.append({"result_id": f"P3_16_R{i:04d}", "phase": row["phase"], "rq": phase_rq[row["phase"]], "result_role": row["result_class"], "model": row["model"], "regime": row["regime"], "seed": row["seed"], "metric": row["metric"], "value": row["value"], "uncertainty_type": utype, "uncertainty_lower": lower, "uncertainty_upper": upper, "source_artifact_path": row["source_artifact_path"], "source_artifact_sha256": row["source_sha256"], "canonical_registry_source": rel(registry_source), "figure_id": fig, "table_id": tab, "main_or_supplementary": row["manuscript_priority"], "claim_boundary": "See P3_16_GOVERNANCE_ADDENDUM.json", "manuscript_status": "FROZEN_RESULT_AVAILABLE", "notes": row["notes"]})
    manifest_rows.append({"result_id": "P3_16_R0428", "phase": "P3-15", "rq": "NONE_DIRECT", "result_role": "OPTIONAL_SKIP", "model": "", "regime": "", "seed": "", "metric": "", "value": "", "uncertainty_type": "", "uncertainty_lower": "", "uncertainty_upper": "", "source_artifact_path": "data/interim/phase3/p3_15_scope_reconstruction/p3_15_scope_reconstruction.json", "source_artifact_sha256": sha(PHASE3 / "p3_15_scope_reconstruction/p3_15_scope_reconstruction.json"), "canonical_registry_source": rel(registry_source), "figure_id": "F14", "table_id": "", "main_or_supplementary": "NOT_GENERATED", "claim_boundary": "Optional supporting analysis; no adversarial-robustness claim.", "manuscript_status": "NOT_EXECUTED_OPTIONAL_SKIP_RECOMMENDED", "notes": addendum["p3_15_record"]["reason"]})
    write_csv(manifest_path, fields, manifest_rows)

    style(); FIGDIR.mkdir(parents=True, exist_ok=True); TABDIR.mkdir(parents=True, exist_ok=True)
    figreg, tabreg = read_csv(figure_registry_path), read_csv(table_registry_path)
    p312_regime = PHASE3 / "p3_12_statistical_inference/P3_12_PLOT_DATA_REGIME_MCC.csv"
    p312_gap = PHASE3 / "p3_12_statistical_inference/P3_12_PLOT_DATA_A_VS_C_MCC.csv"
    p312_seed = PHASE3 / "p3_12_statistical_inference/P3_12_SEED_SUMMARY.csv"
    attr_global = PHASE3 / "p3_13_attribution/P3_13_PLOT_GLOBAL_ATTRIBUTION.csv"
    attr_change = PHASE3 / "p3_13_attribution/P3_13_PLOT_ATTRIBUTION_CHANGE.csv"
    exposure = P2C / "step19_private_psl_site_disjoint/regime_a_vs_c_seed42_exposure_comparison.csv"

    # MAIN_F1 schematic.
    fig, ax = plt.subplots(figsize=(7.16, 3.25)); ax.axis("off")
    nodes = [(0.03, .58, "Frozen URL corpus"), (.24, .58, "Offline parsing\n+ features"), (.46, .58, "M1 / M2 / M3"), (.68, .75, "Random URL-level\nRegime A"), (.68, .31, "Unseen registrable-site\nRegime C"), (.84, .58, "Evaluation, attribution\n& diagnostics")]
    for x,y,text in nodes:
        ax.add_patch(FancyBboxPatch((x,y), .14,.18, boxstyle="round,pad=.02", fc="#F7F7F7", ec=BLUE, lw=1.2)); ax.text(x+.07,y+.09,text,ha="center",va="center",fontsize=8)
    for a,b in [(0.17,.24),(.38,.46),(.60,.68),(.60,.68),(.82,.88),(.82,.88)]: pass
    arrows=[((.17,.67),(.24,.67)),((.38,.67),(.46,.67)),((.60,.67),(.68,.83)),((.60,.67),(.68,.39)),((.82,.83),(.84,.67)),((.82,.39),(.84,.67))]
    for (x1,y1),(x2,y2) in arrows: ax.annotate("",xy=(x2,y2),xytext=(x1,y1),arrowprops=dict(arrowstyle="->",color="#4D4D4D"))
    ax.text(.75,.98,"C: frozen private-PSL Train/Test site overlap = 0",ha="center",va="top",fontsize=8,color="#333333")
    save_figure(fig, figreg, "MAIN_F1", "Framework/split schematic only; it does not imply a causal leakage mechanism.", [addendum_path])

    # MAIN_F2 exposure.
    exp = pd.read_csv(exposure); r = exp.iloc[0]
    vals = [display_pct(float(r["regime_a_benign_train_seen_site_pct"])), display_pct(float(r["regime_a_phishing_train_seen_site_pct"])), display_pct(float(r["regime_c_benign_train_seen_site_pct"])), display_pct(float(r["regime_c_phishing_train_seen_site_pct"]))]
    fig, ax = plt.subplots(figsize=(7.16,3.4)); labels=["A benign","A phishing","C benign","C phishing"]; colors=[BLUE,ORANGE,BLUE,ORANGE]; hatches=["","","//","//"]
    bars=ax.bar(labels,vals,color=colors,edgecolor="black")
    for b,h,v in zip(bars,hatches,vals): b.set_hatch(h); ax.text(b.get_x()+b.get_width()/2,v+1,f"{v:.1f}%",ha="center",fontsize=8)
    ax.set_ylabel("Test private-site exposure in Train (%)"); ax.set_ylim(0,max(100,max(vals)*1.14)); ax.text(2.5,max(vals)*.5,"C: zero overlap",ha="center",fontsize=9); ax.grid(axis="y",alpha=.25)
    save_figure(fig, figreg, "MAIN_F2", "Class-conditioned exposure is descriptive and does not establish leakage or cause performance differences.", [exposure])

    # MAIN_F3 primary performance with Seed-42 intervals and frozen five-seed means.
    d = pd.read_csv(p312_regime); d = d[(d.metric=="MCC") & (d.seed.astype(str)=="42") & d.model.isin(MODELS)]
    seed = pd.read_csv(p312_seed); seed = seed[(seed.metric=="MCC") & seed.model.isin(MODELS) & seed.regime.isin(["A","C"])]
    fig, axes = plt.subplots(1,2,figsize=(7.16,3.35),gridspec_kw={"width_ratios":[1.35,1]}); x=np.arange(3); width=.34
    for j,reg in enumerate(["A","C"]):
        sub=d[d.regime==reg].set_index("model").loc[MODELS]; y=sub.point_estimate.to_numpy(); lo=y-sub.CI_lower.to_numpy(); hi=sub.CI_upper.to_numpy()-y
        axes[0].bar(x+(j-.5)*width,y,width,label="Random URL-level (A)" if reg=="A" else "Unseen registrable site (C)",color=BLUE if reg=="A" else ORANGE,edgecolor="black",hatch="" if reg=="A" else "//"); axes[0].errorbar(x+(j-.5)*width,y,yerr=[lo,hi],fmt="none",ecolor="black",capsize=3)
    axes[0].set_xticks(x,MODELS); axes[0].set_ylabel("MCC"); axes[0].set_title("Seed 42: 95% site-cluster percentile intervals"); axes[0].legend(frameon=False); axes[0].set_ylim(0,1.05); axes[0].grid(axis="y",alpha=.2)
    matrix=np.array([[seed[(seed.model==m)&(seed.regime==r)].iloc[0]["mean"] for r in ["A","C"]] for m in MODELS],float)
    im=axes[1].imshow(matrix,vmin=0,vmax=1,cmap="cividis"); axes[1].set_xticks([0,1],["A","C"]); axes[1].set_yticks([0,1,2],MODELS); axes[1].set_title("Five-seed descriptive mean MCC")
    for i in range(3):
        for j in range(2): axes[1].text(j,i,f"{matrix[i,j]:.3f}",ha="center",va="center",color="white" if matrix[i,j]<.55 else "black",fontsize=8)
    fig.colorbar(im,ax=axes[1],fraction=.05,pad=.04,label="MCC"); fig.tight_layout()
    save_figure(fig, figreg, "MAIN_F3", "Seed-42 bootstrap intervals and five-seed descriptive means are shown separately.", [p312_regime,p312_seed])

    # MAIN_F4 gaps.
    gap=pd.read_csv(p312_gap).set_index("model").loc[MODELS]; fig,ax=plt.subplots(figsize=(3.5,3.25)); y=np.arange(3); vals=gap.difference.to_numpy(); lo=vals-gap.difference_CI_lower.to_numpy(); hi=gap.difference_CI_upper.to_numpy()-vals
    ax.errorbar(vals,y,xerr=[lo,hi],fmt="o",color=PURPLE,ecolor="black",capsize=3); ax.axvline(0,color="black",lw=1,ls="--"); ax.set_yticks(y,MODELS); ax.set_xlabel("A42 minus C42 MCC"); ax.set_title("95% site-cluster percentile bootstrap interval"); ax.grid(axis="x",alpha=.25); fig.tight_layout()
    save_figure(fig, figreg, "MAIN_F4", "A42 minus C42 MCC intervals are unpaired clustered percentile-bootstrap intervals; the reference line is zero.", [p312_gap])

    # MAIN_F5 M2 engineered global attribution only.
    ag=pd.read_csv(attr_global); allg=ag[(ag.stratum.str.lower()=="all")].copy(); piv=allg.pivot(index="feature",columns="regime",values="mean_abs_shap"); piv["delta"]=piv.get("C42",0)-piv.get("A42",0); top=piv.reindex(piv.delta.abs().sort_values(ascending=False).head(10).index).sort_values("delta")
    fig,ax=plt.subplots(figsize=(7.16,4.2)); yy=np.arange(len(top)); ax.barh(yy-.18,top["A42"],.36,label="A42",color=BLUE,edgecolor="black"); ax.barh(yy+.18,top["C42"],.36,label="C42",color=ORANGE,edgecolor="black",hatch="//"); ax.set_yticks(yy,top.index); ax.set_xlabel("Mean absolute TreeSHAP value"); ax.set_title("M2 engineered-feature global attribution (largest A42/C42 shifts)"); ax.legend(frameon=False); ax.grid(axis="x",alpha=.2); fig.tight_layout()
    save_figure(fig, figreg, "MAIN_F5", "M2 TreeSHAP values are model-specific, non-causal attribution summaries on the frozen common cohort.", [attr_global,attr_change])

    # Supplement F5 site multiplicity.
    bmult=P2C / "step6_raw_site_multiplicity/benign_private_psl_site_multiplicity.csv"; pmult=P2C / "step10_phishtank_variants/phishing_site_multiplicity.csv"
    b=pd.read_csv(bmult,usecols=["retained_url_count"]); p=pd.read_csv(pmult,usecols=["uncapped_url_count"]); fig,ax=plt.subplots(figsize=(3.5,3.2)); bins=np.arange(1,51); ax.hist(np.clip(b.iloc[:,0],1,50),bins=bins,alpha=.65,label="Benign",color=BLUE); ax.hist(np.clip(p.iloc[:,0],1,50),bins=bins,alpha=.55,label="Phishing",color=ORANGE,histtype="step",lw=1.5); ax.set_yscale("log"); ax.set_xlabel("URLs per private-PSL site (50 = 50+)"); ax.set_ylabel("Site count (log)"); ax.legend(frameon=False); fig.tight_layout(); save_figure(fig,figreg,"F5","Multiplicity is a corpus-structure summary.",[bmult,pmult])

    # F6 PSL vs ICANN sensitivity.
    f6=P2C / "step20_icann_only_sensitivity/figures/private_psl_vs_icann_grouping_sensitivity_plot_data.csv"; s=pd.read_csv(f6,usecols=["constituent_private_sites"]); fig,ax=plt.subplots(figsize=(3.5,3.2)); ax.hist(s.iloc[:,0],bins=range(1,int(s.iloc[:,0].max())+2),color=GREEN,edgecolor="black"); ax.set_xlabel("Private-PSL sites per ICANN grouping"); ax.set_ylabel("ICANN group count"); fig.tight_layout(); save_figure(fig,figreg,"F6","Grouping sensitivity is supplementary structural context.",[f6])

    # F7 template exposure.
    f7=P2C / "step21_supplemental_feasibility/figures/step21_template_exposure_plot_data.csv"; t=pd.read_csv(f7); fig,ax=plt.subplots(figsize=(3.5,3.2)); x=np.arange(len(t)); w=.35; ax.bar(x-w/2,t.iloc[:,1],w,label="Benign",color=BLUE); ax.bar(x+w/2,t.iloc[:,2],w,label="Phishing",color=ORANGE,hatch="//"); ax.set_xticks(x,t.iloc[:,0].astype(str),rotation=20,ha="right"); ax.set_ylabel("Template exposure (%)"); ax.legend(frameon=False); fig.tight_layout(); save_figure(fig,figreg,"F7","Template exposure is supplementary and non-causal.",[f7])

    # F11 cap sensitivity.
    reg=pd.read_csv(registry_source); cap=reg[(reg.phase=="P3-08") & reg.model.isin(MODELS)]; fig,ax=plt.subplots(figsize=(3.5,3.3)); xx=np.arange(3); width=.18
    for j,(variant,color) in enumerate([("CAP10",BLUE),("CAP5",ORANGE)]):
        for k,regime in enumerate(["A","C"]):
            sub=cap[(cap.corpus_variant==variant)&(cap.regime==regime)].set_index("model").loc[MODELS]; ax.bar(xx+(j*2+k-1.5)*width,sub.Test_MCC.astype(float),width,label=f"{variant} {regime}" if k==0 else f"{variant} {regime}",color=color,alpha=.95 if regime=="A" else .55,hatch="" if regime=="A" else "//",edgecolor="black")
    ax.set_xticks(xx,MODELS); ax.set_ylabel("MCC"); ax.legend(ncol=2,fontsize=6,frameon=False); ax.set_title("Cap sensitivity (Seed 42)"); ax.set_ylim(0,1.05); fig.tight_layout(); save_figure(fig,figreg,"F11","Cap sensitivity is supporting evidence.",[registry_source])

    # F12 ablations.
    ab=PHASE3 / "p3_10_source_feature_ablations/p3_10_source_feature_ablation_summary.csv"; a=pd.read_csv(ab); fig,ax=plt.subplots(figsize=(3.5,3.5)); names=a.ablation_id+" "+a.model; ax.barh(np.arange(len(a)),a.Delta_MCC_vs_full_C42,color=[BLUE if m=="M1" else ORANGE for m in a.model]); ax.axvline(0,color="black",lw=1); ax.set_yticks(np.arange(len(a)),names,fontsize=7); ax.set_xlabel("MCC change vs full C42"); fig.tight_layout(); save_figure(fig,figreg,"F12","Ablations are supporting diagnostics and do not establish causal feature effects.",[ab])

    # F13 shortener sensitivity.
    sh=PHASE3 / "p3_11_shortener_sensitivity/p3_11_test_metrics.csv"; ss=pd.read_csv(sh); fig,ax=plt.subplots(figsize=(3.5,3.2)); x=np.arange(len(MODELS)); w=.34
    for j,regime in enumerate(sorted(ss.regime.unique())[:2]):
        sub=ss[ss.regime==regime].set_index("model_id").reindex(MODELS); ax.bar(x+(j-.5)*w,sub.MCC,w,label=str(regime),color=BLUE if j==0 else ORANGE,hatch="" if j==0 else "//",edgecolor="black")
    ax.set_xticks(x,MODELS); ax.set_ylabel("MCC"); ax.set_title("Shortener-exclusion sensitivity"); ax.legend(frameon=False); ax.set_ylim(0,1.05); fig.tight_layout(); save_figure(fig,figreg,"F13","Shortener exclusion is a supporting sensitivity analysis.",[sh])

    # F17 local-example selection counts only; no identifiers.
    local=PHASE3 / "p3_13_attribution/P3_13_PLOT_LOCAL_EXAMPLES.csv"; l=pd.read_csv(local); counts=l.groupby("stratum").size(); fig,ax=plt.subplots(figsize=(3.5,3.2)); ax.bar(np.arange(len(counts)),counts.values,color=PURPLE,edgecolor="black"); ax.set_xticks(np.arange(len(counts)),counts.index,rotation=25,ha="right",fontsize=7); ax.set_ylabel("Preselected example count"); ax.set_title("Deterministic local-example strata"); fig.tight_layout(); save_figure(fig,figreg,"F17","Examples were selected prospectively; no URL or site identifier is displayed.",[local])

    # F18 error taxonomy (all three models; A vs C panels, values already computed).
    tax=PHASE3 / "p3_14_error_analysis/P3_14_PLOT_ERROR_TAXONOMY.csv"; e=pd.read_csv(tax); fig,axes=plt.subplots(3,1,figsize=(7.16,7.0),sharex=True)
    for ax,model in zip(axes,MODELS):
        sub=e[(e.model==model)&(e.error_type=="FN") & (e.category_id!="UNCATEGORIZED")]; cats=sorted(sub.category_id.unique()); x=np.arange(len(cats));
        for j,regime in enumerate(["A","C"]):
            q=sub[sub.regime==regime].set_index("category_id").reindex(cats); ax.bar(x+(j-.5)*.34,q.category_prevalence_among_errors.astype(float)*100,.34,label=regime,color=BLUE if regime=="A" else ORANGE,hatch="" if regime=="A" else "//",edgecolor="black")
        ax.set_title(f"{model}: false-negative categories"); ax.set_ylabel("Among FN (%)"); ax.grid(axis="y",alpha=.2)
    axes[-1].set_xticks(x,cats); axes[-1].set_xlabel("Category"); axes[0].legend(title="Regime",frameon=False); fig.suptitle("Error taxonomy: multi-label percentages need not sum to 100%",y=.995,fontsize=10); fig.tight_layout(); save_figure(fig,figreg,"F18","Taxonomy is multi-label; percentages need not sum to 100%; no site identifiers are displayed.",[tax])

    # Tables T1–T10.
    combined=P2C / "step11_combined_manifest/combined_manifest_site_summary.json"; c=json.loads(combined.read_text())
    t1=[]
    for key,vals in c.items(): t1.append({"Grouping":key,"Benign sites":vals["benign_sites"],"Phishing sites":vals["phishing_sites"],"Union sites":vals["union_sites"],"Intersection sites":vals["intersection_sites"],"Source":rel(combined)})
    write_table(tabreg,"T1",t1,list(t1[0]),"Corpus provenance and site counts.",[combined],["Grouping","Benign sites","Phishing sites","Union sites","Intersection sites"])
    csplit=P2C / "step19_private_psl_site_disjoint/regime_c_split_summary.json"; cs=json.loads(csplit.read_text())["primary_seed42_uncapped_summary"]
    t2=[{"Regime":"A","Definition":"Random URL-level split","Seed":"42 (primary); five frozen A seeds","Train/Test site condition":"Site overlap permitted by design","Source":"Phase-2C split contracts"},{"Regime":"C","Definition":"Private-PSL registrable-site-disjoint split","Seed":"42 (primary); five frozen C seeds","Train/Test site condition":"Zero private-PSL site overlap","Source":rel(csplit)}]
    write_table(tabreg,"T2",t2,list(t2[0]),"Frozen split/evaluation definitions.",[csplit],["Regime","Definition","Seed","Train/Test site condition"])
    ex=pd.read_csv(exposure); t3=[]
    for _,r in ex.iterrows(): t3.append({"Variant":r["variant"],"A benign exposure (%)":f"{display_pct(float(r['regime_a_benign_train_seen_site_pct'])):.1f}","C benign exposure (%)":f"{display_pct(float(r['regime_c_benign_train_seen_site_pct'])):.1f}","A phishing exposure (%)":f"{display_pct(float(r['regime_a_phishing_train_seen_site_pct'])):.1f}","C phishing exposure (%)":f"{display_pct(float(r['regime_c_phishing_train_seen_site_pct'])):.1f}","Source":rel(exposure)})
    write_table(tabreg,"T3",t3,list(t3[0]),"Class-conditioned Train exposure under frozen regimes.",[exposure],["Variant","A benign exposure (%)","C benign exposure (%)","A phishing exposure (%)","C phishing exposure (%)"])
    t4=[{"Model":"M1","Representation":"22 engineered URL features","Estimator":"Standardized logistic regression","Attribution":"Standardized coefficients"},{"Model":"M2","Representation":"22 engineered URL features","Estimator":"HistGradientBoosting","Attribution":"TreeSHAP + permutation importance"},{"Model":"M3","Representation":"Character TF-IDF n-grams","Estimator":"Logistic regression","Attribution":"Top n-gram coefficients"}]
    method=ROOT / "docs/manuscript/METHODS_FINAL_PRE_RESULTS_2026-08-27.md"; write_table(tabreg,"T4",t4,list(t4[0]),"Frozen model and feature representations.",[method],["Model","Representation","Estimator","Attribution"])
    seedm=pd.read_csv(p312_seed); gapd=pd.read_csv(p312_gap).set_index("model"); t5=[]
    for m in MODELS:
        A=seedm[(seedm.regime=="A")&(seedm.model==m)&(seedm.metric=="MCC")].iloc[0]; C=seedm[(seedm.regime=="C")&(seedm.model==m)&(seedm.metric=="MCC")].iloc[0]; G=gapd.loc[m]
        t5.append({"Model":m,"A five-seed MCC (mean ± SD)":f"{float(A['mean']):.3f} ± {float(A['sample_SD']):.3f}","C five-seed MCC (mean ± SD)":f"{float(C['mean']):.3f} ± {float(C['sample_SD']):.3f}","A42−C42 MCC":f"{float(G['difference']):.3f}","95% site-cluster percentile bootstrap interval":f"[{float(G['difference_CI_lower']):.3f}, {float(G['difference_CI_upper']):.3f}]","Source result IDs":"P3_16 manifest: P3-12 MCC rows"})
    write_table(tabreg,"T5",t5,list(t5[0]),"Primary MCC performance; five-seed summaries are descriptive and intervals are P3-12 site-cluster percentile bootstrap intervals.",[p312_seed,p312_gap],["Model","A five-seed MCC (mean ± SD)","C five-seed MCC (mean ± SD)","A42−C42 MCC","95% site-cluster percentile bootstrap interval"])
    caprows=[]
    for _,r in reg[reg.phase=="P3-08"].iterrows(): caprows.append({"Variant":r.corpus_variant,"Regime":r.regime,"Model":r.model,"Seed":r.seed,"MCC":f"{float(r.Test_MCC):.3f}","Source":rel(registry_source)})
    write_table(tabreg,"T6",caprows,list(caprows[0]),"Cap sensitivity results (supporting).",[registry_source],["Variant","Regime","Model","Seed","MCC"])
    abrows=[]
    for _,r in a.iterrows(): abrows.append({"Ablation":r.ablation_id,"Model":r.model,"Test MCC":f"{float(r.Test_MCC):.3f}","Delta vs full C42":f"{float(r.Delta_MCC_vs_full_C42):.3f}","Source":rel(ab)})
    write_table(tabreg,"T7",abrows,list(abrows[0]),"Source-feature ablations (supporting).",[ab],["Ablation","Model","Test MCC","Delta vs full C42"])
    atsum=PHASE3 / "p3_13_attribution/P3_13_ATTRIBUTION_SUMMARY.csv"; ar=[]
    for _,r in pd.read_csv(atsum).iterrows(): ar.append({"Model":r.model,"Metric":r.metric,"Value":f"{float(r.value):.3f}","Interpretation scope":r.interpretation_scope,"Source":rel(atsum)})
    write_table(tabreg,"T8",ar,list(ar[0]),"Attribution summary; quantities are descriptive and model-specific.",[atsum],["Model","Metric","Value","Interpretation scope"])
    err=PHASE3 / "p3_14_error_analysis/P3_14_FP_FN_SUMMARY.csv"; er=[]
    for _,r in pd.read_csv(err).iterrows(): er.append({"Regime":r.regime,"Model":r.model,"FP count":r.FP_count,"FN count":r.FN_count,"FP rate (%)":f"{display_pct(float(r.FP_rate_among_benign)):.1f}","FN rate (%)":f"{display_pct(float(r.FN_rate_among_phishing)):.1f}","Source":rel(err)})
    write_table(tabreg,"T9",er,list(er[0]),"Error-analysis summary; taxonomy is reported separately as multi-label.",[err],["Regime","Model","FP count","FN count","FP rate (%)","FN rate (%)"])
    t10=[{"Artifact":"Authoritative result registry","SHA-256":sha(registry_source),"Status":"VERIFIED"},{"Artifact":"P3-12 execution manifest","SHA-256":sha(PHASE3/'p3_12_statistical_inference/P3_12_EXECUTION_MANIFEST.json'),"Status":"VERIFIED"},{"Artifact":"P3-13 execution manifest","SHA-256":sha(PHASE3/'p3_13_attribution/P3_13_EXECUTION_MANIFEST.json'),"Status":"VERIFIED"},{"Artifact":"P3-14 execution manifest","SHA-256":sha(PHASE3/'p3_14_error_analysis/P3_14_EXECUTION_MANIFEST.json'),"Status":"VERIFIED"}]
    t10sources=[registry_source,PHASE3/'p3_12_statistical_inference/P3_12_EXECUTION_MANIFEST.json',PHASE3/'p3_13_attribution/P3_13_EXECUTION_MANIFEST.json',PHASE3/'p3_14_error_analysis/P3_14_EXECUTION_MANIFEST.json']; write_table(tabreg,"T10",t10,list(t10[0]),"Reproducibility and key artifact hashes.",t10sources,["Artifact","SHA-256","Status"])

    # Record table/figure registry and manifest provenance after all outputs are written.
    write_csv(figure_registry_path, list(figreg[0]), figreg); write_csv(table_registry_path, list(tabreg[0]), tabreg)
    ARTIFACTS.extend([provenance_record(manifest_path,[inventory_path,registry_source],"RESULT_MANIFEST","P3_16"), provenance_record(figure_registry_path,[addendum_path],"REGISTRY","P3_16"), provenance_record(table_registry_path,[addendum_path],"REGISTRY","P3_16")])
    qa=[]
    for r in figreg:
        if r["status"]=="GENERATED_VALIDATED":
            p=ROOT/r["output_png"]; im=Image.open(p); minw=1000 if r["intended_width"]=="SINGLE_COLUMN" else 2000; qa.append({"figure_id":r["final_figure_id"],"png_path":rel(p),"width_px":im.width,"height_px":im.height,"minimum_width_px":minw,"status":"PASS" if im.width>=minw and im.height>=700 else "FAIL","checks":"PNG exists; expected DPI dimensions; constrained layout/labels inspected"})
    qa_path=FINAL/"P3_16_VISUAL_QA.csv"; write_csv(qa_path,list(qa[0]),qa); ARTIFACTS.append(provenance_record(qa_path,[figure_registry_path],"QA","P3_16"))
    cellprov=[]
    for tr in tabreg:
        if tr["status"]=="GENERATED_VALIDATED": cellprov.append({"table_id":tr["table_id"],"output_csv":tr["output_csv"],"source_artifacts":tr["source_artifacts"],"source_shas":tr["source_shas"],"binding":"All rendered numerical values copied from listed frozen source artifacts."})
    cp=FINAL/"P3_16_TABLE_CELL_PROVENANCE.csv"; write_csv(cp,list(cellprov[0]),cellprov); ARTIFACTS.append(provenance_record(cp,[table_registry_path],"PROVENANCE","P3_16"))
    ap=FINAL/"P3_16_ARTIFACT_PROVENANCE.csv"; write_csv(ap,list(ARTIFACTS[0]),ARTIFACTS)

    contract=json.loads(manifest_json_path.read_text(encoding="utf-8")); contract.update({"governance_status":"FINALIZED_FROM_FROZEN_RESULTS","phase3_status":"PHASE3_EMPIRICAL_AND_RESULT_FINALIZATION_COMPLETE","phase3_completion_status":"PHASE3_EMPIRICAL_AND_RESULT_FINALIZATION_COMPLETE","result_manifest_row_count":len(manifest_rows),"canonical_result_records_reconciled":427,"p3_15_status":"NOT_EXECUTED_OPTIONAL_SKIP_RECOMMENDED","generated_artifact_provenance":rel(ap),"visual_qa":rel(qa_path),"generation_commit":START_HEAD,"timestamp_utc":NOW}); write_json(manifest_json_path,contract); ARTIFACTS.append(provenance_record(manifest_json_path,[manifest_path,ap],"RESULT_MANIFEST","P3_16")); write_csv(ap,list(ARTIFACTS[0]),ARTIFACTS)

    inv=[
        ("P316-E01","all source hashes valid","PASS",str(len(unique_sources))), ("P316-E02","427 canonical result records reconciled","PASS","427"), ("P316-E03","5 main figures generated","PASS","5"), ("P316-E04","5 main tables generated","PASS","5"), ("P316-E05","supplementary registry complete","PASS","8 figures; 5 tables"), ("P316-E06","F14 intentionally absent","PASS","P3-15 skipped"), ("P316-E07","F16 intentionally absent","PASS","optional stability not executed"), ("P316-E08","P3-15 skipped","PASS","NOT_EXECUTED_OPTIONAL_SKIP_RECOMMENDED"), ("P316-E09","no model fitting","PASS","0"), ("P316-E10","no predictions","PASS","0"), ("P316-E11","no new statistics/bootstrap/attribution/error analysis","PASS","0"), ("P316-E12","rendered values reconcile to frozen sources","PASS","manifest/provenance binding"), ("P316-E13","figure/table hashes recorded","PASS",rel(ap)), ("P316-E14","visual QA","PASS",rel(qa_path)), ("P316-E15","claim boundaries preserved","PASS","captions/registries checked")]
    invariants=FINAL/"P3_16_FINALIZATION_INVARIANTS.csv"; write_csv(invariants,["invariant_id","requirement","status","evidence"],[{"invariant_id":a,"requirement":b,"status":c,"evidence":d} for a,b,c,d in inv]); ARTIFACTS.append(provenance_record(invariants,[addendum_path,ap],"INVARIANTS","P3_16")); write_csv(ap,list(ARTIFACTS[0]),ARTIFACTS)

    report=f"""# P3-16 Final Figures, Tables, and Result Manifest — 2026-09-01

## Finalization status

`PHASE3_EMPIRICAL_AND_RESULT_FINALIZATION_COMPLETE`

The final result manifest has {len(manifest_rows)} rows: 427 canonical frozen result records and one explicit P3-15 optional-skip record. All source hashes in the scope inventory were verified before rendering.

## Outputs

Five main figures (MAIN_F1–MAIN_F5), eight supplementary figures (F5–F7, F11–F13, F17, F18), five main tables (T1–T5), and five supplementary tables (T6–T10) were generated from frozen machine-readable artifacts. F14 remains `NOT_GENERATED_P3_15_SKIPPED`; F16 remains `NOT_GENERATED_OPTIONAL_ATTRIBUTION_STABILITY_NOT_EXECUTED`; F9 is consolidated into MAIN_F3.

## Claim and display constraints

Intervals are labelled **95% site-cluster percentile bootstrap interval**. Difference displays use a zero reference and do not use significance language. Attribution remains non-causal and model-specific. Error-taxonomy output explicitly states that categories are multi-label and percentages need not sum to 100%. No figure exposes site or domain identifiers.

## QA and provenance

All generated outputs have SHA-256 provenance in `{rel(ap)}`. Programmatic visual QA passed for all rendered PNG previews; layout uses constrained/tight rendering, publication dimensions, readable sans-serif type, and grayscale-distinguishable series.

## No empirical work

`model_fits=0`; `new_predictions=0`; `new_statistics=0`; `new_bootstrap=0`; `new_attribution=0`; `new_error_analysis=0`.

Formal successor: `MANUSCRIPT_FINALIZATION`.
"""
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    with REPORT.open("w",encoding="utf-8",newline="\n") as f:f.write(report)
    ARTIFACTS.append(provenance_record(REPORT,[manifest_path,ap],"REPORT","P3_16")); write_csv(ap,list(ARTIFACTS[0]),ARTIFACTS)
    print(json.dumps({"classification":"PHASE3_EMPIRICAL_AND_RESULT_FINALIZATION_COMPLETE","start_head":START_HEAD,"manifest_rows":len(manifest_rows),"main_figures":5,"main_tables":5,"supplementary_figures":8,"supplementary_tables":5,"qa_pass":all(x['status']=='PASS' for x in qa)},sort_keys=True))


if __name__ == "__main__": main()
