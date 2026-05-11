"""Password policy enforcement.

Rules (kept simple — too many rules push people to reuse / write down):
  - min 12 characters
  - max 128 characters (bcrypt's hard limit is 72 bytes; we cut earlier so
    the UX is consistent across our hash backends)
  - must contain at least 3 of: lowercase, uppercase, digit, symbol
  - must NOT be on a small bundled blocklist of obvious passwords
"""

from app.core.exceptions import ValidationError

MIN_LEN = 12
MAX_LEN = 72  # bcrypt 72-byte cap

_OBVIOUS = {
    "password", "passw0rd", "p@ssw0rd", "p@ssword",
    "azerty", "qwerty", "qwertz",
    "changeme", "changemenow",
    "letmein", "welcome", "admin1234", "adminadmin",
    "ad-audit-ai", "adauditai",
}


def _classes(pw: str) -> int:
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    return sum([has_lower, has_upper, has_digit, has_symbol])


def validate_password(pw: str, *, user_email: str | None = None) -> None:
    """Raise ValidationError if `pw` doesn't meet policy."""
    if not isinstance(pw, str):
        raise ValidationError("Mot de passe invalide.")
    n = len(pw)
    if n < MIN_LEN:
        raise ValidationError(
            f"Le mot de passe doit contenir au moins {MIN_LEN} caractères "
            f"(actuellement : {n})."
        )
    if n > MAX_LEN:
        raise ValidationError(
            f"Le mot de passe est trop long (maximum {MAX_LEN} caractères)."
        )
    if _classes(pw) < 3:
        raise ValidationError(
            "Le mot de passe doit combiner au moins 3 types parmi : "
            "minuscules, majuscules, chiffres, symboles."
        )
    low = pw.lower()
    if low in _OBVIOUS:
        raise ValidationError(
            "Ce mot de passe est trop courant. Choisissez-en un moins prévisible."
        )
    if user_email:
        local = user_email.split("@", 1)[0].lower()
        if local and local in low:
            raise ValidationError(
                "Le mot de passe ne doit pas contenir votre adresse e-mail."
            )
