"""Login attempt rate limiting.

In-memory sliding-window bucket keyed by (email, ip). 5 attempts per 5-min
window → 15-minute lockout. Resets on a successful login.

This is process-local — fine for a single backend container. For multi-worker
deployments, swap the dict for Redis (see _Bucket).

Rate-limit decisions are advisory: we raise AuthenticationError with a clear
French message rather than HTTP 429 so the UI's existing error-handling
just works.
"""

import logging
import time
from threading import Lock

from app.core.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

# Tunables — exposed for tests
WINDOW_SECONDS = 5 * 60
MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60


class _Bucket:
    def __init__(self) -> None:
        # key (email_lower, ip) → (failure_timestamps[], lockout_until_ts)
        self._state: dict[tuple[str, str], tuple[list[float], float]] = {}
        self._lock = Lock()

    @staticmethod
    def _key(email: str, ip: str) -> tuple[str, str]:
        return (email.lower().strip(), ip or "")

    def check(self, email: str, ip: str) -> None:
        """Raise AuthenticationError if the (email, ip) pair is locked out."""
        now = time.monotonic()
        k = self._key(email, ip)
        with self._lock:
            state = self._state.get(k)
            if not state:
                return
            failures, lockout_until = state
            if lockout_until and lockout_until > now:
                remaining = int(lockout_until - now)
                # Round to nearest minute for a cleaner UX
                mins = max(1, (remaining + 30) // 60)
                raise AuthenticationError(
                    f"Trop de tentatives échouées. "
                    f"Réessayez dans {mins} minute(s)."
                )

    def record_failure(self, email: str, ip: str) -> None:
        now = time.monotonic()
        k = self._key(email, ip)
        with self._lock:
            failures, lockout_until = self._state.get(k, ([], 0.0))
            # Prune failures outside the window
            failures = [t for t in failures if (now - t) < WINDOW_SECONDS]
            failures.append(now)
            if len(failures) >= MAX_FAILURES:
                lockout_until = now + LOCKOUT_SECONDS
                logger.warning(
                    "login_locked_out",
                    extra={"email": email, "ip": ip, "lockout_seconds": LOCKOUT_SECONDS},
                )
            self._state[k] = (failures, lockout_until)

    def record_success(self, email: str, ip: str) -> None:
        with self._lock:
            self._state.pop(self._key(email, ip), None)

    def reset(self) -> None:
        """For tests."""
        with self._lock:
            self._state.clear()


_BUCKET = _Bucket()


def check_login_attempt(email: str, ip: str) -> None:
    _BUCKET.check(email, ip)


def record_login_failure(email: str, ip: str) -> None:
    _BUCKET.record_failure(email, ip)


def record_login_success(email: str, ip: str) -> None:
    _BUCKET.record_success(email, ip)


def _reset_for_tests() -> None:
    _BUCKET.reset()
