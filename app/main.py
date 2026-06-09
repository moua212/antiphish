"""
main.py — FastAPI Phishing Detector
"""

import re, os, time, pickle
from pathlib import Path
from typing import Any, List
import sys
import app.model_classes as model_classes
import numpy as np
import tldextract
from typing import Dict, Any, Literal

from contextlib import asynccontextmanager
from app.database import engine, Base
from app.models import URLHistory
from app.database import init_db

# ⚠️ CRITIQUE : importer AVANT pickle.load()
from app.model_classes import (        # noqa: F401  (pickle en a besoin)
    URLNormalizer,
    ManualFeatureExtractor,
    normalize_url,
    extract_manual_features,
)

from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database import get_db
from app import crud

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════

BASE_DIR   = Path(__file__).resolve().parent
MODEL_PATH = os.getenv("MODEL_PATH", "/app/app/phishing_model.pkl")

TRUSTED_DOMAINS = {
    "google.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "youtube.com", "gmail.com",
    "microsoft.com", "microsoftonline.com", "live.com",
    "outlook.com", "office.com", "office365.com", "azure.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.fr", "amazonaws.com",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
    "twitter.com", "x.com", "linkedin.com", "github.com",
    "paypal.com", "stripe.com", "netflix.com", "spotify.com",
    "wikipedia.org", "reddit.com", "stackoverflow.com",
    "gouv.fr", "service-public.fr", "impots.gouv.fr",
    "ameli.fr", "caf.fr", "pole-emploi.fr",
    "maroc.ma", "gouvernement.ma", "iam.ma",
    "attijariwafabank.com", "cih.co.ma", "bmce.ma",
}

# ══════════════════════════════════════════════════════════════
# CHARGEMENT DU MODÈLE
# ══════════════════════════════════════════════════════════════

def load_model():
    path = Path(MODEL_PATH)
    if not path.exists():
        raise FileNotFoundError(f"Modèle introuvable : {MODEL_PATH}")
    with open(path, "rb") as f:
        data = pickle.load(f)
    print(f"[OK] Modèle chargé — version {data['version']} | "
          f"AUC={data['auc']} | entraîné sur {data['train_size']:,} URLs")
    return data

sys.modules["model_classes"] = model_classes
model_data = load_model()
pipeline   = model_data["pipeline"]

# ══════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════

def get_root_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ""

def classify_url(url: str) -> dict:
    url  = url.strip()
    root = get_root_domain(url)

    if root in TRUSTED_DOMAINS:
        return {
            "url":             url,
            "prediction":      "legitimate",
            "label":           0,
            "confidence":      0.99,
            "score_phishing":  0.01,
            "decision_source": "whitelist",
            "root_domain":     root,
        }

    prob  = float(pipeline.predict_proba([url])[0][1])
    label = int(prob >= 0.5)
    pred  = "phishing" if label == 1 else "legitimate"
    conf  = prob if label == 1 else (1 - prob)

    return {
        "url":             url,
        "prediction":      pred,
        "label":           label,
        "confidence":      round(conf, 4),
        "score_phishing":  round(prob, 4),
        "decision_source": "model",
        "root_domain":     root or "unknown",
    }

def build_pro_response(url: str) -> dict:
    result   = classify_url(url)
    prob     = result["score_phishing"]
    features = extract_manual_features([url])[0]

    return {
        "meta": {
            "model":   "TFIDF-SVM",
            "version": model_data["version"],
        },
        "input": {
            "url":         url,
            "root_domain": result["root_domain"],
        },
        "prediction": {
            "label":      result["prediction"],
            "class":      result["label"],
            "confidence": result["confidence"],
        },
        "probabilities": {
            "legitimate": round(1 - prob, 4),
            "phishing":   prob,
        },
        "risk": {
            "score": prob,
            "level": "high" if prob > 0.7 else "low",
        },
        "features": {
            "url_length":                int(features[0]),
            "dots":                      int(features[1]),
            "slashes":                   int(features[3]),
            "has_ip":                    bool(features[5]),
            "has_suspicious_keywords":   bool(features[6]),
            "has_punycode":              bool(features[7]),
        },
        "explanation": {
            "decision_source": result["decision_source"],
        },
    }

# ══════════════════════════════════════════════════════════════
# SCHÉMAS PYDANTIC
# ══════════════════════════════════════════════════════════════

class URLInput(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL ne peut pas être vide")
        return v

class BatchURLInput(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=100)

class PredictionResult(BaseModel):
    meta:          Dict[str, Any]
    input:         Dict[str, Any]
    prediction:    Dict[str, Any]
    probabilities: Dict[str, float]
    risk:          Dict[str, Any]
    features:      Dict[str, Any]
    explanation:   Dict[str, Any]

class BatchResult(BaseModel):
    count:       int
    phishing:    int
    legitimate:  int
    results:     List[PredictionResult]
    elapsed_ms:  float

# ══════════════════════════════════════════════════════════════
# APP FASTAPI
# ══════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()   # ← exécuté 1 seule fois au démarrage
    yield

app = FastAPI(
    lifespan=lifespan,
    title       = "Phishing URL Detector",
    description = "TF-IDF char-level + LinearSVC",
    version     = model_data["version"],
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Inclure le router historique ──────────────────────────────
from app.routers.history import router as history_router
app.include_router(history_router)

@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start    = time.time()
    response = await call_next(request)
    elapsed  = round((time.time() - start) * 1000, 2)
    response.headers["X-Process-Time-ms"] = str(elapsed)
    return response

# ══════════════════════════════════════════════════════════════
# HELPER — extraire client_id (header optionnel)
# ══════════════════════════════════════════════════════════════

def _get_optional_client(
    x_client_id: str | None = Header(default=None, alias="X-Client-ID")
) -> str | None:
    return x_client_id.strip() if x_client_id else None

# ══════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/health", tags=["Monitoring"])
def health():
    return {
        "status":     "ok",
        "model":      MODEL_PATH,
        "version":    model_data["version"],
        "auc":        model_data["auc"],
        "train_size": model_data["train_size"],
    }


@app.post("/predict", response_model=PredictionResult, tags=["Prédiction"])
async def predict_single(
    body:      URLInput,
    client_id: str | None = Depends(_get_optional_client),
    db:        AsyncSession = Depends(get_db),
):
    """
    Analyse une URL.
    Si le header **X-Client-ID** est fourni, le résultat est sauvegardé
    dans l'historique PostgreSQL.
    """
    try:
        result = build_pro_response(body.url)

        # ── Persistance si client identifié ───────────────────
        if client_id:
            await crud.save_url_result(db, client_id, result)

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch", response_model=BatchResult, tags=["Prédiction"])
async def predict_batch(
    body:      BatchURLInput,
    client_id: str | None = Depends(_get_optional_client),
    db:        AsyncSession = Depends(get_db),
):
    """
    Analyse plusieurs URLs en une seule requête (max 100).
    Si **X-Client-ID** est fourni, chaque résultat est historisé.
    """
    try:
        start   = time.time()
        results = [build_pro_response(url) for url in body.urls]
        elapsed = round((time.time() - start) * 1000, 2)

        # ── Persistance batch ─────────────────────────────────
        if client_id:
            for r in results:
                await crud.save_url_result(db, client_id, r)

        n_phish = sum(1 for r in results if r["prediction"]["class"] == 1)
        return {
            "count":      len(results),
            "phishing":   n_phish,
            "legitimate": len(results) - n_phish,
            "results":    results,
            "elapsed_ms": elapsed,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/test-db", tags=["Database"])
async def test_db(db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(text("SELECT 1"))
        value  = result.scalar()
        return {"status": "success", "database": "connected", "result": value}
    except Exception as e:
        return {"status": "error", "database": "failed", "detail": str(e)}
