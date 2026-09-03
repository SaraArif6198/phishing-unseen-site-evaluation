# Model Definitions & Representation Families

- **M1**: 22 engineered URL-only features, standardized via Train-fitted `StandardScaler`, classified with `LogisticRegression`.
- **M2**: 22 engineered URL-only features, fitted with `HistGradientBoostingClassifier(early_stopping=False)`.
- **M3**: Raw URL string character n-grams ($n \in [2, 6]$), vectorized via Train-fitted `TfidfVectorizer`, classified with `LogisticRegression`.
- **B1**: Single-feature (`url_length`) Logistic Regression baseline.
- **B2**: Categorical (`public_suffix_private`) OneHotEncoder Logistic Regression baseline.
