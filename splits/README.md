# Frozen Split Manifests & Privacy-Safe Grouping Definitions

This directory contains frozen split metadata:
- **`split_regimes_summary.csv`**: Overview of Regimes A, B, C, and D, random seeds, and site isolation conditions.
- **`frozen_manifests/`**: Privacy-safe split assignment summaries containing record identifiers, partition tags, and anonymized site hashes.

## Safety & Privacy Protocol
Split definitions do not expose raw URL strings or sensitive infrastructure details. All partition memberships are deterministically verifiable via the frozen split SHA-256 manifests.
