"""
predict.py — VS Code
─────────────────────
Charge phishing_model.pkl et prédit des URLs.

Structure du projet :
    mon_projet/
    ├── phishing_model.pkl   ← généré par Jupyter
    └── predict.py           ← ce fichier

Installation :
    pip install scikit-learn pandas numpy tldextract
"""

import pickle, re
import tldextract
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import MaxAbsScaler

# ──────────────────────────────────────────────
# IMPORTANT : recopier les classes du notebook
# sklearn en a besoin pour désérialiser le .pkl
# ──────────────────────────────────────────────

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
        return pd.Series(X).apply(normalize_url)

class ManualFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): return self
    def transform(self, X):
        urls = X if isinstance(X, pd.Series) else pd.Series(X)
        return extract_manual_features(urls.apply(normalize_url))

# ──────────────────────────────────────────────
# WHITELIST — domaines toujours légitimes
# ──────────────────────────────────────────────

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "microsoftonline.com",
    "apple.com", "paypal.com", "amazon.com", "amazon.fr",
    "github.com", "wikipedia.org", "netflix.com",
    "gouv.fr", "service-public.fr", "ameli.fr",
    "attijariwafabank.com", "iam.ma", "cih.co.ma",
}

def get_root_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.domain else ""

# ──────────────────────────────────────────────
# CHARGEMENT DU MODÈLE
# ──────────────────────────────────────────────

with open("phishing_model.pkl", "rb") as f:
    model_data = pickle.load(f)

pipeline = model_data["pipeline"]
print(f"✅ Modèle chargé | AUC={model_data['auc']} | v{model_data['version']}")

# ──────────────────────────────────────────────
# FONCTION DE PRÉDICTION
# ──────────────────────────────────────────────

def predict(url: str) -> dict:
    """
    Retourne un dict avec :
      - prediction  : "phishing" ou "legitimate"
      - confidence  : certitude 0-1
      - score       : probabilité brute phishing
      - source      : "whitelist" ou "model"
    """
    root = get_root_domain(url)

    if root in TRUSTED_DOMAINS:
        return {
            "url":        url,
            "prediction": "legitimate",
            "confidence": 0.99,
            "score":      0.01,
            "source":     "whitelist",
        }

    score = float(pipeline.predict_proba([url])[0][1])
    pred  = "phishing" if score >= 0.5 else "legitimate"
    conf  = score if pred == "phishing" else 1 - score

    return {
        "url":        url,
        "prediction": pred,
        "confidence": round(conf, 4),
        "score":      round(score, 4),
        "source":     "model",
    }

def predict_batch(urls: list) -> list:
    """Prédit une liste d'URLs."""
    return [predict(url) for url in urls]

# ──────────────────────────────────────────────
# EXEMPLE D'UTILISATION
# ──────────────────────────────────────────────

if __name__ == "__main__":

    test_urls = [
        # Légitimes
        "google.com",
        "accounts.google.com/signin/v2/identifier",
        "www.impots.gouv.fr/accueil",
        "support.apple.com/fr-fr/iphone",
        # Phishing
        "paypal-secure-login-account-verify.com",
        "https://www.youtube.com/results?search_query=issam+adoch",
        "192.168.0.1/admin/login.php",
        "xn--pypal-4ve.com/signin",
        "secure-irs-tax-refund.com/gov/claim",
    ]

    print("\n" + "═" * 62)
    print(f"  {'URL':<40} {'RÉSULTAT':<12} {'SCORE':>6}")
    print("═" * 62)

    for url in test_urls:
        r     = predict(url)
        emoji = "🔴" if r["prediction"] == "phishing" else "🟢"
        tag   = f"[{r['source']}]"
        print(f"  {emoji} {url[:38]:<38} {r['prediction']:<12} {r['score']:>5.1%}  {tag}")

    print("═" * 62)

    # ── Prédiction simple sur 1 URL ──────────────────────────
    result = predict("paypal-verify-account-now.com")
    print(f"\nRésultat : {result}")
    # {'url': '...', 'prediction': 'phishing', 'confidence': 0.999, 'score': 0.999, 'source': 'model'}
