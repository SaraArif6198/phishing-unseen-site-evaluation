# Frozen Split Regime Definitions

This directory contains frozen split regime documentation:
- **`frozen_manifests/split_regimes_summary.csv`**: Overview of Regimes A, B, C, and D, random seeds, and site isolation conditions.

## Split Execution Invariants
- **Regime A**: Stratified random URL-level split across seeds `{13, 42, 73, 101, 2026}`.
- **Regime B**: Hostname-disjoint diagnostic split under seed `42`.
- **Regime C**: Private-PSL registrable-site-disjoint split across seeds `{42, 123, 456, 789, 1234}` (primary).
- **Regime D**: ICANN-only parent site-disjoint split under seed `42`.

Partition membership SHA-256 digests are recorded in `manifests/hashes/reproducibility_hashes.csv`.
