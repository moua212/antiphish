# app/crud.py

from datetime import datetime, timedelta, timezone
from typing import List
from sqlalchemy import select, func, desc, cast, Date, extract
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import URLHistory


# ══════════════════════════════════════════════════════════════
# ÉCRITURE
# ══════════════════════════════════════════════════════════════

async def save_url_result(
    db: AsyncSession,
    client_id: str,
    pro_result: dict,
) -> URLHistory:
    entry = URLHistory(
        client_id       = client_id,
        url             = pro_result["input"]["url"],
        root_domain     = pro_result["input"]["root_domain"],
        prediction      = pro_result["prediction"]["label"],
        label           = pro_result["prediction"]["class"],
        confidence      = pro_result["prediction"]["confidence"],
        score_phishing  = pro_result["probabilities"]["phishing"],
        decision_source = pro_result["explanation"]["decision_source"],
        risk_level      = pro_result["risk"]["level"],
        features        = pro_result.get("features"),
        model_version   = pro_result["meta"]["version"],
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


# ══════════════════════════════════════════════════════════════
# LECTURE — historique paginé
# ══════════════════════════════════════════════════════════════

async def get_history(
    db: AsyncSession,
    client_id: str,
    page: int = 1,
    page_size: int = 20,
) -> tuple[int, List[URLHistory]]:
    offset = (page - 1) * page_size
    count_q = (
        select(func.count())
        .select_from(URLHistory)
        .where(URLHistory.client_id == client_id)
    )
    total = (await db.execute(count_q)).scalar_one()
    rows_q = (
        select(URLHistory)
        .where(URLHistory.client_id == client_id)
        .order_by(desc(URLHistory.created_at))
        .offset(offset)
        .limit(page_size)
    )
    rows = (await db.execute(rows_q)).scalars().all()
    return total, list(rows)


# ══════════════════════════════════════════════════════════════
# STATS
# ══════════════════════════════════════════════════════════════

async def get_history_stats(
    db: AsyncSession,
    client_id: str,
) -> dict:
    q = (
        select(
            func.count().label("total"),
            func.sum(URLHistory.label).label("phishing"),
            func.max(URLHistory.created_at).label("last_scan"),
        )
        .where(URLHistory.client_id == client_id)
    )
    row = (await db.execute(q)).one()
    total    = row.total or 0
    phishing = int(row.phishing or 0)
    return {
        "client_id":        client_id,
        "total_scanned":    total,
        "total_phishing":   phishing,
        "total_legitimate": total - phishing,
        "phishing_rate":    round(phishing / total, 4) if total else 0.0,
        "last_scan":        row.last_scan,
    }


# ══════════════════════════════════════════════════════════════
# TIMELINE — scans par jour
# ══════════════════════════════════════════════════════════════

async def get_timeline(
    db: AsyncSession,
    client_id: str,
    days: int = 30,
) -> list:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = (
        select(
            cast(URLHistory.created_at, Date).label("day"),
            func.count().label("total"),
            func.sum(URLHistory.label).label("phishing"),
        )
        .where(
            URLHistory.client_id == client_id,
            URLHistory.created_at >= since,
        )
        .group_by(cast(URLHistory.created_at, Date))
        .order_by(cast(URLHistory.created_at, Date))
    )
    rows = (await db.execute(q)).all()
    return [
        {
            "day":        str(row.day),
            "total":      row.total,
            "phishing":   int(row.phishing or 0),
            "legitimate": row.total - int(row.phishing or 0),
        }
        for row in rows
    ]


# ══════════════════════════════════════════════════════════════
# HOURLY — scans par heure
# ══════════════════════════════════════════════════════════════

async def get_hourly(
    db: AsyncSession,
    client_id: str,
) -> list:
    q = (
        select(
            extract("hour", URLHistory.created_at).label("hour"),
            func.count().label("total"),
            func.sum(URLHistory.label).label("phishing"),
        )
        .where(URLHistory.client_id == client_id)
        .group_by(extract("hour", URLHistory.created_at))
        .order_by(extract("hour", URLHistory.created_at))
    )
    rows = (await db.execute(q)).all()
    result = {i: {"hour": i, "total": 0, "phishing": 0} for i in range(24)}
    for row in rows:
        h = int(row.hour)
        result[h] = {
            "hour":     h,
            "total":    row.total,
            "phishing": int(row.phishing or 0),
        }
    return list(result.values())


# ══════════════════════════════════════════════════════════════
# TOP DOMAINES phishing
# ══════════════════════════════════════════════════════════════

async def get_top_domains(
    db: AsyncSession,
    client_id: str,
    limit: int = 10,
) -> list:
    q = (
        select(
            URLHistory.root_domain,
            func.count().label("total"),
            func.avg(URLHistory.score_phishing).label("avg_score"),
        )
        .where(
            URLHistory.client_id == client_id,
            URLHistory.label == 1,
            URLHistory.root_domain != "unknown",
        )
        .group_by(URLHistory.root_domain)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    rows = (await db.execute(q)).all()
    return [
        {
            "domain":    row.root_domain,
            "count":     row.total,
            "avg_score": round(float(row.avg_score or 0), 3),
        }
        for row in rows
    ]


# ══════════════════════════════════════════════════════════════
# SUPPRESSION
# ══════════════════════════════════════════════════════════════

async def delete_history(
    db: AsyncSession,
    client_id: str,
) -> int:
    q = select(URLHistory).where(URLHistory.client_id == client_id)
    rows = (await db.execute(q)).scalars().all()
    count = len(rows)
    for row in rows:
        await db.delete(row)
    await db.commit()
    return count
