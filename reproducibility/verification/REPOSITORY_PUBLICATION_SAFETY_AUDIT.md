# REPOSITORY PUBLICATION SAFETY AUDIT

**Repository:** `phishing-unseen-site-evaluation`  
**Date:** 2026-09-03  
**Status:** `PASS — AUDITED & READY FOR PRIVATE REMOTE CREATION`

---

## ?? AUDIT CHECKLIST

| Category | Item | Result | Notes |
|---|---|---|---|
| **Manuscript Isolation** | Manuscript .md / .docx / .pdf files | **0** | No paper drafts or manuscript files present |
| **Data Sharing Governance** | Raw URL dumps / non-redistributable corpora | **0** | Data README provided; raw URLs excluded pending terms verification |
| **Quarantined Site Names** | Specific quarantined registrable site names | **0** | All specific site names excluded |
| **Publication Claims** | unsupported journal or unlive GitHub URL claims | **0** | Citation updated to neutral submission format |
| **Security & Credentials** | Tokens, API keys, passwords, credentials | **0** | Clean |
| **Path Safety** | Hardcoded absolute local user paths | **0** | All paths relative or configuration-bound |
| **Source Code Integrity** | Python execution modules | **15 files** | Cleaned and organized across `src/` subdirectories |
| **Model Definitions** | Authoritative model execution scripts | **Present** | Definitions live in `src/evaluation/` frozen runners |
| **Reproducibility Manifests** | Frozen split regime definitions and SHA-256 hashes | **Present** | SHA-256 digests in `manifests/hashes/` |
| **Canonical Results** | Primary, diagnostic, attribution, bootstrap, error CSVs | **Present** | All frozen aggregate result tables included |
| **Figures** | Publication-quality figures (PNG, SVG, PDF) | **21 files** | MAIN_F1 to MAIN_F7 included |
| **Environment Specifications** | requirements.txt, python_version.txt, environment_snapshot.txt | **Present** | Python 3.10.11 locked stack (SHAP 0.49.1 verified) |
| **Publication File Inventory** | `PUBLICATION_FILE_INVENTORY.csv` exact count match | **90 files** | `tracked git files == inventory rows` (exact match) |
| **Scientific Freeze** | Scientific values, seeds, metrics, or models altered | **0** | Science 100% frozen |

---

## ?? CONCLUSION
The `phishing-unseen-site-evaluation` repository has been fully audited following the R1R publication-safety and file-level reconciliation pass. All safety, privacy, metadata, and reproducibility criteria are satisfied.
