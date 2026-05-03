"""Tests for password hashing and JWT helpers."""

import pytest

from app.core.exceptions import AuthenticationError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify_round_trip(self):
        password = "M0nMotDePasse!"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed) is True

    def test_wrong_password_rejected(self):
        hashed = hash_password("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_same_password_yields_different_hashes(self):
        a = hash_password("same")
        b = hash_password("same")
        assert a != b


class TestJWT:
    def test_access_token_round_trip(self):
        token = create_access_token("user-123", "admin")
        decoded = decode_token(token)
        assert decoded["sub"] == "user-123"
        assert decoded["role"] == "admin"
        assert decoded["type"] == "access"

    def test_refresh_token_marked_correctly(self):
        token = create_refresh_token("user-456", "auditor")
        decoded = decode_token(token)
        assert decoded["type"] == "refresh"
        assert decoded["role"] == "auditor"

    def test_invalid_token_rejected(self):
        with pytest.raises(AuthenticationError):
            decode_token("not.a.valid.jwt")
