# Non-Parametric Site-Cluster Percentile Bootstrap Module

Executes class-stratified private-PSL registrable-site cluster percentile bootstrap ($B=2,000$ replicates, master seed 99, two-sided 95% limits).

## Methodology & Invariants
- **Cluster Unit**: `site_key_private` (URLs are never treated as independent resampling units).
- **Stratification**: Class-stratified (benign and phishing site-clusters sampled independently with replacement).
- **Unpaired Contrast**: Independently samples native Test sets under A42 and C42 to compute $\Delta\text{MCC} = \text{MCC}_A - \text{MCC}_C$ distribution.
