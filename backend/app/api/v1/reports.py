"""PDF report generation endpoint."""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.engagement_access import require_analysis_access
from app.core.exceptions import NotFoundError, ValidationError
from app.core.security import get_current_user
from app.database import get_db
from app.models.analysis import Analysis, AttackPath
from app.models.engagement import Engagement

logger = logging.getLogger(__name__)
router = APIRouter(tags=["reports"])


@router.get("/analyses/{analysis_id}/report.pdf")
async def download_report(
    db: Annotated[AsyncSession, Depends(get_db)],
    analysis: Annotated[Analysis, Depends(require_analysis_access("viewer"))],
):
    analysis_id = analysis.id
    if analysis.status != "completed":
        raise ValidationError("L'analyse n'est pas encore terminée")

    engagement_result = await db.execute(
        select(Engagement).where(Engagement.id == analysis.engagement_id)
    )
    engagement = engagement_result.scalar_one_or_none()

    paths_result = await db.execute(
        select(AttackPath)
        .where(AttackPath.analysis_id == analysis_id)
        .options(selectinload(AttackPath.mitre_techniques))
        .order_by(AttackPath.global_score.desc().nullslast())
    )
    paths = paths_result.scalars().all()

    from app.modules.report import generate_pdf

    pdf_bytes = await generate_pdf(analysis, engagement, paths)

    filename = f"rapport_{engagement.code if engagement else analysis_id}_{analysis_id.hex[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
