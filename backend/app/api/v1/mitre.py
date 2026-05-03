"""MITRE ATT&CK coverage endpoint."""

import logging
import uuid
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import NotFoundError
from app.core.security import get_current_user
from app.database import get_db
from app.models.analysis import Analysis, AttackPath
from app.schemas.analysis import MitreCoverageResponse, MitreTechniqueResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["mitre"])


@router.get("/analyses/{analysis_id}/mitre", response_model=MitreCoverageResponse)
async def get_mitre_coverage(
    analysis_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user=Depends(get_current_user),
):
    result_check = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    if not result_check.scalar_one_or_none():
        raise NotFoundError("Analyse")

    paths_result = await db.execute(
        select(AttackPath)
        .where(AttackPath.analysis_id == analysis_id)
        .options(selectinload(AttackPath.mitre_techniques))
    )
    paths = paths_result.scalars().all()

    seen: dict[str, MitreTechniqueResponse] = {}
    tactic_counter: Counter = Counter()
    tech_counter: Counter = Counter()

    for path in paths:
        for mt in path.mitre_techniques:
            seen[mt.technique_id] = MitreTechniqueResponse(
                technique_id=mt.technique_id,
                technique_name=mt.technique_name,
                tactic=mt.tactic,
                url=mt.url,
            )
            tactic_counter[mt.tactic] += 1
            tech_counter[mt.technique_id] += 1

    top_techniques = [
        {"technique_id": tid, "count": cnt, "technique_name": seen[tid].technique_name}
        for tid, cnt in tech_counter.most_common(10)
    ]

    return MitreCoverageResponse(
        analysis_id=analysis_id,
        techniques=list(seen.values()),
        count_by_tactic=dict(tactic_counter),
        top_techniques=top_techniques,
    )
