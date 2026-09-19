# Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation

[![Release](https://img.shields.io/github/v/release/SaraArif6198/phishing-unseen-site-evaluation)](https://github.com/SaraArif6198/phishing-unseen-site-evaluation/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10](https://img.shields.io/badge/Python-3.10-blue.svg)](environment/python_version.txt)

Reproducibility repository for the manuscript:

**Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation**

This repository contains the frozen code, configuration contracts, result summaries, manifests, environment records, and reproducibility documentation supporting the study. The work evaluates how phishing-URL performance and attribution behavior change when moving from conventional random URL-level evaluation to private-PSL registrable-site-disjoint evaluation.

The repository documents a frozen research analysis. It is not a live phishing-detection service and does not make a deployment-performance claim.

---

## Quick links

- [Latest revision-support release](https://github.com/SaraArif6198/phishing-unseen-site-evaluation/releases/tag/v1.1-revision-support)
- [Original paper-submission release](https://github.com/SaraArif6198/phishing-unseen-site-evaluation/releases/tag/v1.0-paper-submission)
- [Authoritative result registry](results/primary/PHASE3_AUTHORITATIVE_RESULT_REGISTRY.csv)
- [Site-exposure results](results/primary/T3_site_exposure.csv)
- [Primary MCC results](results/primary/T5_mcc_performance.csv)
- [Full bootstrap confidence-interval summary](results/bootstrap/P3_12_CI_SUMMARY.csv)
- [Primary MCC bootstrap intervals](results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv)
- [Attribution summary](results/attribution/T8_attribution_summary.csv)
- [Error-analysis summary](results/error_analysis/T9_error_summary.csv)
- [Split definitions](splits/frozen_manifests/split_regimes_summary.csv)
- [Reproducibility documentation](reproducibility/README.md)
- [Data provenance and sharing policy](data/README.md)
- [Citation metadata](CITATION.cff)

---

## Study scope

Random URL-level partitioning can place different URLs from the same registrable site in both Train and Test partitions. This study quantifies that exposure separately for benign and phishing Test URLs and compares it with a zero-overlap private-PSL registrable-site-disjoint evaluation.

The study evaluates three compact URL-only representation families:

| Model | Representation | Estimator |
|---|---|---|
| M1 | 22 engineered URL features | Standardized logistic regression |
| M2 | Same 22 engineered URL features | `HistGradientBoostingClassifier` |
| M3 | Character TF-IDF n-grams | Logistic regression |

Attribution analyses are descriptive and are interpreted within model family only. Attribution magnitudes are not compared directly across M1, M2, and M3.

---

## Evaluation design

### Regime A: random URL-level evaluation

Regime A uses label-stratified 70/15/15 Train/Validation/Test partitions over the frozen seeds:

`13, 42, 73, 101, 2026`

Site overlap between Train and Test is permitted by design.

### Regime C: registrable-site-disjoint evaluation

Regime C assigns private-PSL registrable-site groups atomically to 70/15/15 partitions over the frozen seeds:

`42, 123, 456, 789, 1234`

A registrable-site group appears in only one partition, giving zero private-PSL registrable-site overlap across Train, Validation, and Test.

### Seed 42 comparison context

Seed 42 is the A-side matched-analysis seed and the primary Regime-C split used for the direct A42–C42 comparison.

All five Regime-A seeds remain formally equal for aggregate reporting. Five-seed summaries are descriptive and are not treated as seed-level inferential samples.

### Model selection and decision threshold

- preprocessing is fit within each Train partition;
- hyperparameters are selected using Validation MCC;
- Test outcomes are not used for threshold selection;
- binary predictions use a fixed probability threshold of `0.5`;
- threshold tuning is excluded from the experimental protocol.

---

## Class-conditioned site exposure

A Test URL is defined as **site-exposed** when its frozen private-PSL registrable-site key is also present among Train URLs.

Class-conditioned site exposure is therefore the percentage of Test URLs in a given class whose registrable site occurs in Train.

Under the primary Seed-42 comparison:

| Regime | Benign Test exposure | Phishing Test exposure |
|---|---:|---:|
| A42 | 99.7% | 64.6% |
| C42 | 0.0% | 0.0% |

Detailed exposure outputs are available in:

[`results/primary/T3_site_exposure.csv`](results/primary/T3_site_exposure.csv)

---

## Primary performance results

Matthews correlation coefficient (MCC) is the primary performance metric.

Five-seed descriptive means are:

| Model | Regime A MCC | Regime C MCC |
|---|---:|---:|
| M1 | 0.613 ± 0.011 | 0.585 ± 0.056 |
| M2 | 0.905 ± 0.003 | 0.770 ± 0.066 |
| M3 | 0.974 ± 0.002 | 0.863 ± 0.031 |

For the direct A42-C42 comparison, the MCC differences were:

| Model | A42-C42 MCC difference | 95% site-cluster interval |
|---|---:|---:|
| M1 | 0.095 | [-0.039, 0.235] |
| M2 | 0.200 | [0.102, 0.315] |
| M3 | 0.151 | [0.082, 0.247] |

Canonical performance results are available in:

[`results/primary/T5_mcc_performance.csv`](results/primary/T5_mcc_performance.csv)

---

## Statistical uncertainty

Statistical uncertainty was estimated using a non-parametric, class-stratified private-PSL registrable-site cluster percentile bootstrap.

The frozen protocol uses:

- 2,000 bootstrap replicates;
- two-sided 95% percentile intervals;
- private-PSL registrable sites as the resampling unit;
- separate benign and phishing site-cluster pools;
- sampling with replacement;
- all URLs from each selected site cluster;
- master seed `99`.

URLs are not treated as independent bootstrap units.

### Primary and secondary uncertainty

MCC is the primary metric.

The frozen file:

[`results/bootstrap/P3_12_CI_SUMMARY.csv`](results/bootstrap/P3_12_CI_SUMMARY.csv)

contains 95% site-cluster percentile intervals for nine performance metrics across 30 canonical Regime-A/Regime-C seed-model identities:

- MCC
- PR-AUC
- Macro F1
- phishing recall
- precision
- false-positive rate
- specificity
- balanced accuracy
- ROC-AUC

Only MCC has a direct native A42–C42 difference interval.

The remaining intervals are supporting descriptive uncertainty summaries. Five-seed summaries are descriptive, seeds are not bootstrap units, and no p-values were generated.

The compact primary MCC interval output is available in:

[`results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv`](results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv)

---

## Attribution analysis

Attribution comparisons are performed within model family.

### M1

M1 uses logistic-regression coefficients on Train-standardized engineered URL features.

### M2

M2 uses TreeSHAP with raw model output and no supplied background dataset. Permutation importance is retained as supporting model-specific evidence.

### M3

M3 uses character n-gram logistic-regression coefficient summaries, including shared-vocabulary comparisons across regimes.

Because these attribution quantities are defined on different model-specific scales, their magnitudes are not interpreted as directly comparable across model families.

Frozen attribution summaries are available in:

[`results/attribution/T8_attribution_summary.csv`](results/attribution/T8_attribution_summary.csv)

---

## Repository structure

```text
.
├── README.md
├── CITATION.cff
├── LICENSE
├── requirements.txt
├── configs/
│   ├── README.md
│   └── hyperparameter_contract.json
├── data/
│   └── README.md
├── environment/
│   ├── environment_snapshot.txt
│   ├── python_version.txt
│   └── requirements_detected.txt
├── figures/
│   └── README.md
├── manifests/
│   ├── corpus/
│   └── hashes/
├── reproducibility/
│   ├── README.md
│   ├── provenance/
│   └── verification/
├── results/
│   ├── attribution/
│   ├── bootstrap/
│   ├── diagnostics/
│   ├── error_analysis/
│   └── primary/
├── splits/
│   ├── README.md
│   └── frozen_manifests/
└── src/
    ├── acquisition/
    ├── attribution/
    ├── audit/
    ├── bootstrap/
    ├── evaluation/
    ├── features/
    ├── models/
    ├── parsing/
    └── splits/
```

---

## Key reproducibility artifacts

| Purpose | Artifact |
|---|---|
| Authoritative result registry | [`results/primary/PHASE3_AUTHORITATIVE_RESULT_REGISTRY.csv`](results/primary/PHASE3_AUTHORITATIVE_RESULT_REGISTRY.csv) |
| Corpus provenance | [`results/primary/T1_corpus_provenance.csv`](results/primary/T1_corpus_provenance.csv) |
| Split definitions | [`results/primary/T2_split_definitions.csv`](results/primary/T2_split_definitions.csv) |
| Site exposure | [`results/primary/T3_site_exposure.csv`](results/primary/T3_site_exposure.csv) |
| Model representations | [`results/primary/T4_model_representations.csv`](results/primary/T4_model_representations.csv) |
| Primary MCC results | [`results/primary/T5_mcc_performance.csv`](results/primary/T5_mcc_performance.csv) |
| Cap sensitivity | [`results/diagnostics/T6_cap_sensitivity.csv`](results/diagnostics/T6_cap_sensitivity.csv) |
| Feature ablations | [`results/diagnostics/T7_feature_ablations.csv`](results/diagnostics/T7_feature_ablations.csv) |
| Attribution summary | [`results/attribution/T8_attribution_summary.csv`](results/attribution/T8_attribution_summary.csv) |
| Error-analysis summary | [`results/error_analysis/T9_error_summary.csv`](results/error_analysis/T9_error_summary.csv) |
| Primary MCC bootstrap intervals | [`results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv`](results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv) |
| Full bootstrap uncertainty summary | [`results/bootstrap/P3_12_CI_SUMMARY.csv`](results/bootstrap/P3_12_CI_SUMMARY.csv) | 
| Split-regime summary | [`splits/frozen_manifests/split_regimes_summary.csv`](splits/frozen_manifests/split_regimes_summary.csv) |
| Reproducibility hashes | [`manifests/hashes/reproducibility_hashes.csv`](manifests/hashes/reproducibility_hashes.csv) |
| Parser contract | [`manifests/corpus/parser_contract_manifest.json`](manifests/corpus/parser_contract_manifest.json) |
| Hyperparameter contract | [`configs/hyperparameter_contract.json`](configs/hyperparameter_contract.json) |

---

## Reproducibility

The repository preserves the frozen analysis configuration and supporting evidence required to document the reported protocol.

Key controls include:

- Train-specific preprocessing;
- Validation-MCC hyperparameter selection;
- fixed 0.5 decision threshold;
- no threshold tuning;
- frozen evaluation seeds;
- frozen parser and PSL contract;
- deterministic feature definitions;
- model-specific selection records;
- frozen result summaries;
- SHA-256 artifact hashes;
- recorded execution environment.

The main reproducibility documentation is available in:

[`reproducibility/README.md`](reproducibility/README.md)

Environment information is available under:

[`environment/`](environment/)

The core execution environment uses Python `3.10.11`.

---

## Running the code

Install the recorded Python dependencies with:

```bash
pip install -r requirements.txt
```

The repository is primarily a reproducibility archive of the frozen research workflow rather than a single-command application.

Relevant execution scripts are organized by analysis stage under `src/`, including:

- corpus acquisition;
- URL parsing;
- engineered feature extraction;
- primary evaluation;
- sensitivity and ablation analysis;
- statistical uncertainty;
- attribution analysis;
- error analysis.

The scripts reference frozen research artifacts and manifests that may not all be redistributed in this public repository because of source-data and redistribution constraints. Consult the relevant directory README before attempting to replay an analysis stage.

---

## Data availability

The primary corpus was constructed from:

- a frozen PhishTank online-valid phishing snapshot;
- Common Crawl `CC-MAIN-2026-30`;
- a frozen 2,500-site Tranco sampling frame;
- a frozen Public Suffix List snapshot.

The final post-quarantine analysis corpus contains:

- 124,154 URLs;
- 52,589 benign URLs;
- 71,565 phishing URLs;
- 29,091 private-PSL registrable sites.

Raw URL strings and the combined derived corpus are not redistributed through this repository while multi-source redistribution eligibility remains subject to source-provider conditions.

The repository instead provides:

- corpus provenance documentation;
- acquisition and parsing code;
- frozen configuration contracts;
- parser and PSL manifests;
- split definitions;
- aggregate scientific results;
- statistical uncertainty outputs;
- environment information;
- reproducibility hashes.

Third-party source materials remain subject to their original providers' access, licensing, and redistribution conditions.

See:

[`data/README.md`](data/README.md)

---

## Code availability

Code and reproducibility artifacts supporting the study are publicly available in this repository:

https://github.com/SaraArif6198/phishing-unseen-site-evaluation

For the journal-revision reproducibility state, use:

[`v1.1-revision-support`](https://github.com/SaraArif6198/phishing-unseen-site-evaluation/releases/tag/v1.1-revision-support)

The revision-support release adds documentation and previously retained frozen reproducibility outputs, including the secondary bootstrap confidence-interval summary.

No experiment, model fit, split, prediction, bootstrap interval, attribution result, or reported scientific result was recomputed for this release.

---

## Release history

### `v1.1-revision-support`

Revision-support release associated with the revised manuscript.

This release:

- publishes the previously retained frozen secondary confidence-interval summary;
- clarifies the primary-versus-secondary uncertainty hierarchy;
- improves public reproducibility documentation;
- preserves the original submitted scientific results;
- contains no scientific recomputation.

### `v1.0-paper-submission`

Frozen repository state corresponding to the original paper submission.

The historical release manifest at:

[`reproducibility/provenance/RELEASE_MANIFEST.json`](reproducibility/provenance/RELEASE_MANIFEST.json)

records the immutable `v1.0-paper-submission` state.

It is intentionally retained as historical provenance and is not replaced by the later revision-support release.

---

## Manuscript status

The associated manuscript is currently under revision.

This repository and its releases document reproducibility states of the research and do not imply journal acceptance or publication.

A DOI, journal volume, issue, page range, or acceptance status will not be added unless formally assigned by the journal.

---

## Citation

Citation metadata are provided in:

[`CITATION.cff`](CITATION.cff)

GitHub can use this file to generate citation information for the repository.

Until formal journal publication metadata are available, please cite the repository using the information supplied in `CITATION.cff`.

---

## License

Repository code and original documentation are released under the MIT License.

See:

[`LICENSE`](LICENSE)

The repository license does not override the terms of third-party datasets, URL sources, Tranco material, Common Crawl resources, PhishTank data, or Public Suffix List material.

Those resources remain governed by their respective providers' terms and licenses.

---

## Research-use notice

Results in this repository are specific to the frozen corpus, evaluation design, and model configurations described in the manuscript.

The repository does not establish:

- operational phishing-detection performance;
- zero-day detection capability;
- causal shortcut learning;
- causal attribution effects;
- universal superiority of a model family;
- deployment generalization beyond the evaluated setting.
