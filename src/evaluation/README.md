# Model Evaluation & Metric Computation Module

Scripts for executing evaluation across splits, regimes, and model families:
- `execute_p3_04_regime_a_seed42_pilot.py`: Regime A pilot execution.
- `execute_p3_05_c42.py`: Primary Regime C Seed 42 evaluation.
- `execute_p3_06_regime_a.py`: 5-seed Regime A evaluation.
- `execute_p3_07_regime_c.py`: 5-seed Regime C evaluation.
- `execute_p3_08_cap_seed42.py`: Cap-10 and Cap-5 multiplicity sensitivity.
- `execute_p3_09_regime_bd.py`: Hostname (Regime B) and ICANN-only (Regime D) diagnostics.
- `execute_p3_10_ablations.py`: Feature ablation analysis (AB1--AB5b).

Computes 9 canonical metrics (MCC, PR-AUC, ROC-AUC, Macro F1, Phishing recall, Precision, Specificity, FPR, Balanced accuracy).
