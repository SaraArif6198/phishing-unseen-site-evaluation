# Reproducibility verification and execution governance

This directory contains verification guidance, execution manifests, and frozen SHA-256 records for the reported analyses.

## Verification scope

The repository records split-specific Train-only preprocessing, Validation-MCC hyperparameter selection, a fixed 0.5 threshold with no threshold tuning, and Test evaluation after selection.

## Statistical uncertainty

MCC is the primary metric. results/bootstrap/P3_12_CI_SUMMARY.csv contains 95% class-stratified site-cluster percentile intervals for MCC and eight secondary metrics across 30 canonical Regime-A/Regime-C seed-model identities. It records 2,000 bootstrap replicates, a 0.95 confidence level, site_key_private as the cluster key, and master seed 99. Only MCC has a direct native A42-C42 difference interval; secondary intervals and five-seed summaries are descriptive. No p-values were generated.

## Hash verification

Key hashes are recorded in manifests/hashes/reproducibility_hashes.csv. The revision-support release preserves v1.0-paper-submission.
