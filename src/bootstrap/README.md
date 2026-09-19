# Nonparametric site-cluster percentile bootstrap module

This module implements the frozen class-stratified private-PSL registrable-site percentile bootstrap used for the reported uncertainty analyses.

## Frozen method

- Cluster unit: site_key_private; URLs are not treated as independent resampling units.
- Stratification: benign and phishing site clusters are sampled independently with replacement.
- Replicates: 2,000 per canonical identity, with two-sided 95% percentile limits and master seed 99.
- Native comparison: A42 and C42 native Test sets are independently resampled for the MCC A42-C42 contrast; this is unpaired.
- Inference scope: MCC is primary. Intervals for eight secondary metrics are supporting and descriptive; no p-values or seed-level tests were generated.

## Public outputs

- results/bootstrap/P3_12_site_cluster_bootstrap_intervals.csv is the compact three-model MCC interval table used in the manuscript.
- results/bootstrap/P3_12_CI_SUMMARY.csv is the frozen 270-row interval summary for MCC and eight secondary metrics across 30 canonical identities.
