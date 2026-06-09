# app/models.py

from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Boolean,
    Integer, DateTime, JSON, Index
)
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.database import Base


class URLHistory(Base):
    __tablename__ = "url_history"

    # ── Clé primaire ──────────────────────────────────────────
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ── Identification client ─────────────────────────────────
    client_id = Column(String(128), nullable=False, index=True)

    # ── URL analysée ──────────────────────────────────────────
    url         = Column(String(2048), nullable=False)
    root_domain = Column(String(253),  nullable=True)

    # ── Résultat de prédiction ────────────────────────────────
    prediction      = Column(String(16),  nullable=False)   # "phishing" | "legitimate"
    label           = Column(Integer,     nullable=False)    # 0 | 1
    confidence      = Column(Float,       nullable=False)
    score_phishing  = Column(Float,       nullable=False)
    decision_source = Column(String(32),  nullable=False)   # "model" | "whitelist"

    # ── Niveau de risque ─────────────────────────────────────
    risk_level = Column(String(8), nullable=False)          # "high" | "low"

    # ── Features extraites (optionnel mais utile) ─────────────
    features = Column(JSON, nullable=True)

    # ── Métadonnées ───────────────────────────────────────────
    model_version = Column(String(16), nullable=True)
    created_at    = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Index composite pour les requêtes fréquentes ─────────
    __table_args__ = (
        Index("ix_url_history_client_created", "client_id", "created_at"),
    )

    def __repr__(self):
        return (
            f"<URLHistory id={self.id} client={self.client_id} "
            f"url={self.url[:40]!r} pred={self.prediction}>"
        )
