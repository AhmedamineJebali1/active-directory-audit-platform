"""SQLAlchemy models — imported here so Alembic discovers all metadata."""

from app.models.user import User  # noqa: F401
from app.models.engagement import Engagement  # noqa: F401
from app.models.analysis import Analysis, AttackPath, PathMitreTechnique  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.setting import AppSetting  # noqa: F401
