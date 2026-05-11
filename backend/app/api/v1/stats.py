"""Analysis statistics endpoint."""

import logging
import uuid
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.engagement_access import require_analysis_access
from app.core.exceptions import NotFoundError
from app.core.security import get_current_user
from app.database import get_db
from app.models.analysis import Analysis, AttackPath, PathMitreTechnique
from app.schemas.analysis import AnalysisStatsResponse, AttackPathResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["stats"])


@router.get("/analyses/{analysis_id}/stats", response_model=AnalysisStatsResponse)
async def get_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
):
    analysis_id = analysis.id
    paths_result = await db.execute(
        select(AttackPath)
        .where(AttackPath.analysis_id == analysis_id)
        .options(selectinload(AttackPath.mitre_techniques))
    )
    paths = paths_result.scalars().all()

    by_risk: dict[str, int] = {}
    scores = []
    tech_counter: Counter = Counter()

    for p in paths:
        if p.risk_level:
            by_risk[p.risk_level] = by_risk.get(p.risk_level, 0) + 1
        if p.global_score is not None:
            scores.append(p.global_score)
        for mt in p.mitre_techniques:
            tech_counter[mt.technique_id] += 1

    avg_score = sum(scores) / len(scores) if scores else 0.0
    top_techniques = [
        {"technique_id": tid, "count": cnt}
        for tid, cnt in tech_counter.most_common(10)
    ]

    top_paths = sorted(
        [p for p in paths if p.global_score is not None],
        key=lambda x: x.global_score,
        reverse=True,
    )[:5]

    return AnalysisStatsResponse(
        analysis_id=analysis_id,
        total_paths=len(paths),
        by_risk_level=by_risk,
        avg_global_score=round(avg_score, 2),
        top_techniques=top_techniques,
        top_paths=[AttackPathResponse.model_validate(p) for p in top_paths],
    )
