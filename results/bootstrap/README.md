# Bootstrap uncertainty outputs

This directory contains frozen statistical uncertainty outputs associated with the reported analyses.

## Public artifacts

- P3_12_CI_SUMMARY.csv is the retained 270-row site-cluster bootstrap summary. It covers 30 canonical regime-seed-model identities and nine metrics: MCC, Macro F1, Balanced Accuracy, Precision, Phishing Recall, Specificity, FPR, ROC-AUC, and PR-AUC. Each interval uses 2,000 non-parametric class-stratified site-cluster bootstrap replicates and a 95% confidence level.
- P3_12_site_cluster_bootstrap_intervals.csv is the compact three-row MCC interval table retained for the principal A42, C42, and A42-C42 comparison.

MCC is the primary metric. The secondary metric intervals are supporting descriptive uncertainty outputs. Five-seed summaries are descriptive, seeds are not inferential units, and no p-values are reported. These files are frozen outputs; no intervals were recomputed for the revision.

The CSV summary intentionally contains aggregate statistical outputs only. It does not redistribute raw URL data, private site keys, or split assignments.
