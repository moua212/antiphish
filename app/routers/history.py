# app/routers/history.py

from fastapi import APIRouter, Depends, HTTPException, Query, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import HistoryResponse, HistoryStats
from app import crud

router = APIRouter(prefix="/history", tags=["Historique"])


def _require_client(
    x_client_id: str | None = Header(default=None, alias="X-Client-ID")
) -> str:
    if not x_client_id or not x_client_id.strip():
        raise HTTPException(
            status_code=401,
            detail="Header X-Client-ID requis.",
        )
    return x_client_id.strip()


# ══════════════════════════════════════════════════════════════
# GET /history — liste paginée
# ══════════════════════════════════════════════════════════════

@router.get("", response_model=HistoryResponse)
async def list_history(
    page:      int          = Query(1,  ge=1),
    page_size: int          = Query(20, ge=1, le=200),
    client_id: str          = Depends(_require_client),
    db:        AsyncSession = Depends(get_db),
):
    total, rows = await crud.get_history(db, client_id, page, page_size)
    return {
        "client_id": client_id,
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "results":   rows,
    }


# ══════════════════════════════════════════════════════════════
# GET /history/stats
# ══════════════════════════════════════════════════════════════

@router.get("/stats", response_model=HistoryStats)
async def history_stats(
    client_id: str          = Depends(_require_client),
    db:        AsyncSession = Depends(get_db),
):
    return await crud.get_history_stats(db, client_id)


# ══════════════════════════════════════════════════════════════
# GET /history/timeline
# ══════════════════════════════════════════════════════════════

@router.get("/timeline")
async def get_timeline(
    days:      int          = Query(30, ge=1, le=365),
    client_id: str          = Depends(_require_client),
    db:        AsyncSession = Depends(get_db),
):
    return await crud.get_timeline(db, client_id, days)


# ══════════════════════════════════════════════════════════════
# GET /history/hourly
# ══════════════════════════════════════════════════════════════

@router.get("/hourly")
async def get_hourly(
    client_id: str          = Depends(_require_client),
    db:        AsyncSession = Depends(get_db),
):
    return await crud.get_hourly(db, client_id)


# ══════════════════════════════════════════════════════════════
# GET /history/top-domains
# ══════════════════════════════════════════════════════════════

@router.get("/top-domains")
async def get_top_domains(
    limit:     int          = Query(10, ge=1, le=50),
    client_id: str          = Depends(_require_client),
    db:        AsyncSession = Depends(get_db),
):
    return await crud.get_top_domains(db, client_id, limit)


# ══════════════════════════════════════════════════════════════
# DELETE /history — RGPD
# ══════════════════════════════════════════════════════════════

@router.delete("")
async def clear_history(
    client_id: str          = Depends(_require_client),
    db:        AsyncSession = Depends(get_db),
):
    deleted = await crud.delete_history(db, client_id)
    return {
        "status":  "ok",
        "deleted": deleted,
        "message": f"{deleted} entrée(s) supprimée(s).",
    }
