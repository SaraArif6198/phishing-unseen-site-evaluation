# Dataset Construction, Provenance & Sharing Policy

This document describes the provenance, acquisition procedure, and redistribution status of the evaluation corpus analyzed in the study:

> **Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation**

---

## 📊 Corpus Provenance & Composition

The primary evaluation corpus comprises **124,154 DNS-host URLs**:
- **Phishing Stream**: **71,565 URLs** (57.6%) originating from **27,668** unique private-PSL registrable sites.
  - *Source*: PhishTank online-valid snapshot dated `2026-08-17` (`phishtank_verified_online.jsonl`).
- **Benign Stream**: **52,589 URLs** (42.4%) originating from **1,423** unique private-PSL registrable sites.
  - *Source*: Common Crawl `CC-MAIN-2026-30` archived page index sampled for a persistent 2,500-site Tranco sampling frame (`tranco_top2500_sites.jsonl`).
- **Total Registrable Sites**: **29,091** private-PSL registrable sites across both classes.
- **Mixed-Label Site Quarantine**: Exactly **five mixed-label private-PSL registrable sites** containing **175 total rows** (161 Benign, 14 Phishing) were quarantined as whole sites. No individual URL labels were reclassified.

---

## 🔒 Data Redistribution Policy

> [!IMPORTANT]
> The raw URL strings and combined derived corpus are **not currently redistributed directly** in this repository pending formal verification of multi-source redistribution eligibility under applicable terms.

### Included Reproducibility Materials
To ensure full scientific auditability without violating third-party terms, this repository includes:
1. **Source Stream Acquisition Scripts**: `src/acquisition/` scripts for recreating the PhishTank snapshot and Tranco frame.
2. **Parser & PSL Contracts**: `src/parsing/` modules anchored to the frozen official Public Suffix List snapshot (`public_suffix_list_2026-08-17.dat`, SHA-256: `155b43d46932e933f622365225e7861288c36a45380b1f7d00b3d09748926226`).
3. **Split Regime Summaries**: `splits/` definitions specifying partitioning logic and random seeds.
4. **Canonical Result Records**: `results/` CSVs documenting canonical aggregate result records supporting reported evaluation metrics, sensitivity analyses, bootstrap intervals, attribution summaries, and error analyses.
5. **SHA-256 Hash Manifests**: `manifests/hashes/` records for verifying dataset byte identity.

---

## 📜 Third-Party Data Terms Note

Code and scripts in this repository are licensed under the [MIT License](../LICENSE). Third-party source materials (PhishTank, Common Crawl, Tranco, Public Suffix List) remain governed by their original terms. Raw and derived URL data are not redistributed in this repository pending final eligibility review.
