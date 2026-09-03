# Beyond Random Splits: Reproducibility Artifacts for Phishing URL Evaluation

This repository provides frozen reproducibility artifacts, execution utilities, evaluation metrics, statistical bootstrap outputs, attribution summaries, figures, and environment manifests for the scientific paper:

> **Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation**  
> *Sara Arif* (Department of Computer Science, University of Chakwal, Pakistan)

---

## 📌 Overview & Scope

Evaluation protocols in URL-based phishing detection predominantly rely on random URL-level train-test splits. Under random partitioning, distinct URLs belonging to the same registrable site can appear in both training and test partitions, creating **class-conditioned train-test site exposure**.

This study presents a controlled empirical evaluation comparing:
- **Regime A (Random URL-Level Comparator):** Conventional 70/15/15 stratified random URL-level split over 5 frozen seeds (`{13, 42, 73, 101, 2026}`).
- **Regime C (Primary Private-PSL Site-Disjoint Split):** Group-atomic partitioning enforcing zero registrable-site overlap (`0.0%` test exposure) over 5 frozen seeds (`{42, 123, 456, 789, 1234}`).

Evaluated representation and model families:
- **M1:** Transparent engineered linear model (Logistic Regression over 22 standardized URL features).
- **M2:** Nonlinear tree-based engineered-feature model (`sklearn.ensemble.HistGradientBoostingClassifier`).
- **M3:** Sparse character-level representation (Character $n$-gram TF-IDF $n \in [2, 6]$ + Logistic Regression).

---

## 📁 Repository Structure

```
phishing-unseen-site-evaluation/
├── README.md                 # Primary publication & reproducibility documentation
├── LICENSE                   # MIT Code License
├── CITATION.cff              # Machine-readable metadata citation
├── requirements.txt          # Python package requirements
├── environment/              # Python environment specs and runtime lock
├── src/                      # Cleaned python execution modules
│   ├── acquisition/          # Source stream acquisition scripts
│   ├── parsing/              # IDNA UTS-46 & Public Suffix List parsing
│   ├── features/             # 22-feature engineered URL vectorization
│   ├── audit/                # Source-structure & multiplicity audits
│   ├── splits/               # Stratified random and site-disjoint splitters
│   ├── models/               # Model family documentation
│   ├── evaluation/           # Frozen execution runners & canonical metrics
│   ├── bootstrap/            # Site-cluster percentile bootstrap
│   └── attribution/          # Within-model feature attribution
├── configs/                  # Hyperparameter contracts & search grids
├── splits/                   # Frozen split regime definitions
├── manifests/                # Provenance and SHA-256 verification records
├── results/                  # Canonical aggregate output CSVs & diagnostic tables
├── figures/                  # Publication-ready figures (PNG, SVG, PDF)
├── data/                     # Data acquisition and sharing guidance
└── reproducibility/          # Artifact verification instructions & hashes
```

---

## 🔒 Provenance & Reproducibility Notice

> [!NOTE]
> This repository is a curated reproducibility release assembled from frozen research artifacts. All split regime definitions, hyperparameter selection rules, metric values, bootstrap intervals, and attribution rankings are frozen and hash-verified.

For detailed hash verification procedures, see [`reproducibility/README.md`](reproducibility/README.md).  
For dataset acquisition guidelines and redistribution terms, see [`data/README.md`](data/README.md).

---

## 📜 Citation

If you reference this work or utilize these reproducibility artifacts, please cite:

```bibtex
@misc{arif2026beyond,
  author       = {Sara Arif},
  title        = {Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation},
  year         = {2026},
  note         = {Manuscript and associated reproducibility artifacts}
}
```
