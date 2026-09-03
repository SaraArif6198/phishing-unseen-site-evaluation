# Partitioning and Split Construction Module

Provides partitioning logic for constructing evaluation split regimes:
- **Regime A**: Conventional 70/15/15 stratified random URL-level split.
- **Regime B**: Hostname-disjoint diagnostic split.
- **Regime C**: Private-PSL registrable-site-disjoint split (primary).
- **Regime D**: ICANN-only registrable-site-disjoint diagnostic split.

Enforces zero-overlap invariants across Train, Validation, and Test sets.
