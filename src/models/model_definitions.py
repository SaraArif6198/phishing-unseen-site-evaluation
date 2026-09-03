"""
Model Family Definitions for Phishing URL Evaluation.

Provides scikit-learn pipeline constructors for:
- M1: Engineered features + StandardScaler + Logistic Regression
- M2: Engineered features + HistGradientBoostingClassifier
- M3: Character n-gram TF-IDF + Logistic Regression
- B1: Single-feature (url_length) Logistic Regression baseline
- B2: Categorical (public_suffix_private) OneHotEncoder + Logistic Regression baseline
"""
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

def create_m1_pipeline(C: float = 1.0) -> Pipeline:
    return Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(C=C, solver='lbfgs', max_iter=1000, random_state=42))
    ])

def create_m2_model(learning_rate: float = 0.1, max_iter: int = 100, max_leaf_nodes: int = 31) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        learning_rate=learning_rate,
        max_iter=max_iter,
        max_leaf_nodes=max_leaf_nodes,
        early_stopping=False,
        random_state=42
    )

def create_m3_pipeline(C: float = 1.0, max_features: int = 50000) -> Pipeline:
    return Pipeline([
        ('vectorizer', TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 6),
            sublinear_tf=True,
            min_df=5,
            norm='l2',
            max_features=max_features
        )),
        ('classifier', LogisticRegression(C=C, solver='lbfgs', max_iter=1000, random_state=42))
    ])

def create_b1_baseline() -> Pipeline:
    return Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(C=1.0, solver='lbfgs', max_iter=1000, random_state=42))
    ])

def create_b2_baseline() -> Pipeline:
    return Pipeline([
        ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False)),
        ('classifier', LogisticRegression(C=1.0, solver='lbfgs', max_iter=1000, random_state=42))
    ])
