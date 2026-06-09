"""
model_classes.py — Classes custom du pipeline sklearn.
DOIT être importé dans tout fichier qui charge phishing_model.pkl
"""

import re
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


def normalize_url(url: str) -> str:
    url = url.lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    url = re.sub(r'\s+', '', url)
    return url


def extract_manual_features(urls) -> np.ndarray:
    feats = []
    for url in urls:
        u = str(url)
        feats.append([
            len(u),
            u.count('.'),
            u.count('-'),
            u.count('/'),
            u.count('@'),
            int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u))),
            int(bool(re.search(r'(verify|secure|login|update|account|confirm|billing|suspend)', u))),
            int(bool(re.search(r'xn--', u))),
        ])
    return np.array(feats, dtype=np.float32)


class URLNormalizer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): return self
    def transform(self, X):
        if isinstance(X, pd.Series):
            return X.apply(normalize_url)
        return pd.Series(X).apply(normalize_url)


class ManualFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): return self
    def transform(self, X):
        urls = X if isinstance(X, pd.Series) else pd.Series(X)
        return extract_manual_features(urls.apply(normalize_url))