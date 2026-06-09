# app/schemas.py

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════
# Schéma de lecture (DB → API)
# ══════════════════════════════════════════════════════════════

class HistoryItem(BaseModel):
    id:              UUID
    client_id:       str
    url:             str
    root_domain:     Optional[str]
    prediction:      str
    label:           int
    confidence:      float
    score_phishing:  float
    decision_source: str
    risk_level:      str
    features:        Optional[Dict[str, Any]]
    model_version:   Optional[str]
    created_at:      datetime

    model_config = {"from_attributes": True}   # Pydantic v2


# ══════════════════════════════════════════════════════════════
# Réponse paginée
# ══════════════════════════════════════════════════════════════

class HistoryResponse(BaseModel):
    client_id:  str
    total:      int
    page:       int
    page_size:  int
    results:    List[HistoryItem]


# ══════════════════════════════════════════════════════════════
# Stats résumées
# ══════════════════════════════════════════════════════════════

class HistoryStats(BaseModel):
    client_id:       str
    total_scanned:   int
    total_phishing:  int
    total_legitimate: int
    phishing_rate:   float          # 0.0 – 1.0
    last_scan:       Optional[datetime]
