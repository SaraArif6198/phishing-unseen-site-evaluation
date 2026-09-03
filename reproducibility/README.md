# Reproducibility Verification & Execution Governance

This directory contains verification instructions, execution manifests, and frozen SHA-256 hashes to enable independent verification of all scientific outputs reported in the paper.

---

## 🔍 SHA-256 Verification Guide

Key artifact hashes recorded in `manifests/hashes/reproducibility_hashes.csv`:

| Artifact | SHA-256 Digest | Status |
|---|---|---|
| Authoritative Result Registry | `4aa5ee0e5926372a389f55ce6f2c47171941a7f38292179d94ecfc4bc5ded4b4` | VERIFIED |
| P3-12 Bootstrap Execution Manifest | `3aba1c96b8f240fa790a14d699ef6047f522e850ff5da8e62087b24949614f78` | VERIFIED |
| P3-13 Attribution Execution Manifest | `0e3a23488ca179d4eaaf8bfd9f3f0bab1b48508d44005a5b7ab400f8570a0716` | VERIFIED |
| P3-14 Error Analysis Execution Manifest | `87437307db7d9e8cfde0889682a3475895300e0dddbb7e0b335563fd19a4f5c4` | VERIFIED |
| Post-Quarantine Primary DNS Corpus | `b850a96bda433c4d7207ae97a139d18692781b5bb70d2b5a13ef7920c467972d` | VERIFIED |
| Mixed-Label Quarantine Candidates | `96e0cc5b1f1fa314fc2d988686786055edb637ef8f5fc91d10bd1694af487ebc` | VERIFIED |
| Frozen Public Suffix List (2026-08-17) | `155b43d46932e933f622365225e7861288c36a45380b1f7d00b3d09748926226` | VERIFIED |

---

## ⚡ Execution Invariants & Fail-Loud Governance

1. **Train-Only Fitting Boundary**: Scalers (`StandardScaler`), vectorizers (`TfidfVectorizer`), and model weights MUST be fit strictly on Train partitions. Cross-partition fitting is prohibited.
2. **Validation-Only Tuning Boundary**: Hyperparameter optimization is evaluated solely on Validation MCC.
3. **Strict Test Isolation**: Test partitions remain untouched throughout model selection and hyperparameter tuning.
4. **Locked Decision Threshold**: Classification decision threshold is strictly fixed at `0.5`. Threshold tuning is prohibited.
