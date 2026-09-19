# Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation

This repository provides frozen code, configuration, result summaries, manifests, and documentation supporting the manuscript Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation. It documents a controlled comparison between random URL-level evaluation and registrable-site-disjoint evaluation; it is not a live detection service or a deployment claim.

## Overview

Random URL-level partitions can place different URLs from the same registrable site in both training and Test data. The study quantifies class-conditioned site exposure under random URL-level and private-PSL registrable-site-disjoint regimes. M1 uses standardized engineered URL features with logistic regression, M2 uses engineered features with histogram gradient boosting, and M3 uses character n-gram TF-IDF with logistic regression. Attribution summaries are descriptive and interpreted within model family only.

## Manuscript

The associated manuscript is under revision. This repository is a reproducibility release for frozen reported analyses; it does not imply journal acceptance.

## Key evaluation design

- Regime A uses 70/15/15 label-stratified random URL-level partitions with frozen seeds 13, 42, 73, 101, and 2026.
- Regime C assigns private-PSL registrable-site groups atomically to 70/15/15 partitions with frozen seeds 42, 123, 456, 789, and 1234.
- Seed 42 is the A-side matched-analysis seed and the primary Regime-C split for the direct A42-C42 context. All five Regime-A seeds remain equal for aggregate reporting.
- Predictions use a fixed 0.5 threshold. Hyperparameters are selected using Validation MCC; threshold tuning is excluded.
- Statistical uncertainty uses class-stratified whole-registrable-site percentile bootstrap resampling.

## Repository structure

- configs: frozen model and selection contracts
- data: provenance and redistribution guidance
- environment: environment specifications
- figures: reported figures
- manifests: hashes and artifact manifests
- reproducibility: verification and execution-governance guidance
- results: canonical aggregate outputs, including bootstrap summaries
- splits: frozen split definitions
- src: acquisition, parsing, feature, evaluation, bootstrap, and attribution code

## Reproducibility

Preprocessing is fit within each Train partition, hyperparameters are selected on Validation MCC, and Test evaluation follows selection. Split definitions, seed registries, environment records, and SHA-256 manifests document the frozen protocol.

## Primary results

Canonical aggregate results are in results/primary. Reported values are specific to the frozen corpus and evaluation protocol and are not presented as a deployment guarantee.

## Statistical uncertainty

MCC is the primary performance metric. The frozen file results/bootstrap/P3_12_CI_SUMMARY.csv contains 95% site-cluster percentile intervals for MCC and eight secondary metrics across 30 canonical Regime-A/Regime-C seed-model identities. Only MCC has a direct native A42-C42 difference interval. Secondary intervals are supporting and descriptive; five-seed summaries are descriptive and no p-values were generated. The compact manuscript MCC interval table remains at results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv.

## Attribution analysis

M1 uses coefficients on Train-standardized features, M2 uses raw-model-output TreeSHAP values, and M3 uses coefficient summaries over its character representation. Their magnitudes are not directly comparable across model families.

## Data availability

Data provenance, corpus-construction records, split definitions, and derived reproducibility artifacts are documented here. Source datasets remain subject to their providers access and redistribution conditions. Raw URL strings and the combined derived corpus are not redistributed pending verification of multi-source redistribution eligibility. The repository provides code, frozen metadata, manifests, and result artifacts that document the reported protocol.

## Code availability

Code and reproducibility artifacts supporting the study are publicly available in this repository. The v1.1-revision-support release adds documentation and previously retained frozen reproducibility artifacts without recomputing analyses or changing reported scientific results.

## Citation

Please use CITATION.cff. The manuscript has no repository-invented DOI or publication metadata.

## License

Repository code and documentation are licensed under the MIT License. Third-party source datasets and Public Suffix List material remain subject to their original terms; see data/README.md.

## Reproducibility release history

- v1.0-paper-submission preserves the repository state corresponding to the original submitted manuscript.
- v1.1-revision-support adds documentation and the previously retained frozen secondary confidence-interval summary. No scientific analysis was recomputed.
