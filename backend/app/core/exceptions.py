"""Custom business exceptions."""

from fastapi import HTTPException, status


class AuthenticationError(HTTPException):
    def __init__(self, detail: str = "Authentification requise"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class AuthorizationError(HTTPException):
    def __init__(self, detail: str = "Accès non autorisé"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class NotFoundError(HTTPException):
    def __init__(self, resource: str = "Ressource"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} introuvable",
        )


class ValidationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)


class ConflictError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)


class IngestionError(Exception):
    """Raised when BloodHound JSON ingestion fails."""

    def __init__(self, message: str, source: str = ""):
        super().__init__(message)
        self.source = source


class LLMProviderError(Exception):
    """Raised when LLM provider call fails after retries."""

    def __init__(self, message: str, provider: str = "", attempts: int = 0):
        super().__init__(message)
        self.provider = provider
        self.attempts = attempts


class GraphError(Exception):
    """Raised when graph operations fail."""


class ReportGenerationError(Exception):
    """Raised when PDF generation fails."""
