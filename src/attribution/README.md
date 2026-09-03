# Within-Model Feature Attribution Module

Quantifies feature attribution change between Regime A and Regime C on the frozen common cohort of 2,801 URLs:

- **M1**: Standardized logistic regression signed and absolute coefficients.
- **M2**: TreeSHAP values (`feature_perturbation='tree_path_dependent'`) + Permutation Importance (30 repetitions).
- **M3**: Top character $n$-gram coefficients and shared-vocabulary overlap analysis.

Attribution metrics are model-specific and within-model; values are not compared across different model families.
