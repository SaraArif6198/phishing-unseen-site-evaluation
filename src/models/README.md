# Model Definitions & Representation Families

Authoritative model pipeline construction is implemented directly within the frozen executed scripts under `src/evaluation/` (e.g., `execute_p3_04_regime_a_seed42_pilot.py`, `execute_p3_05_c42.py`, `execute_p3_06_regime_a.py`, `execute_p3_07_regime_c.py`).

## Evaluated Model Families
- **M1**: 22 engineered URL-only features, standardized via Train-fitted `StandardScaler`, classified with `LogisticRegression`.
- **M2**: 22 engineered URL-only features, fitted with `sklearn.ensemble.HistGradientBoostingClassifier(early_stopping=False)` (nonlinear tree-based engineered-feature model).
- **M3**: Raw URL string character n-grams ($n \in [2, 6]$), vectorized via Train-fitted `TfidfVectorizer`, classified with `LogisticRegression`.
- **B1**: Single-feature (`url_length`) Logistic Regression baseline.
- **B2**: Categorical (`public_suffix_private`) OneHotEncoder Logistic Regression baseline.
