from __future__ import annotations

"""Self-describing reversible secret tokens for field/entity privacy protection."""

import base64
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from privacy_gateway.errors import TextCryptoError, TextCryptoKeyError
from privacy_gateway.services.presidio_crypto import TextCryptoService


DEFAULT_SECRET_LABEL = "secret"
DEFAULT_SECRET_VERSION = "1"
KDF_ITERATIONS = 200_000
SALT_BYTES = 16
TOKEN_BODY_PATTERN = r"([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)"
GENERIC_TOKEN_PATTERN = re.compile(rf"<([a-z0-9_-]+):([a-z0-9_-]+):{TOKEN_BODY_PATTERN}>")


@dataclass(frozen=True)
class SecretTokenMatch:
    """Location and payload for a protected secret token in text."""

    start: int
    end: int
    token: str
    ciphertext: str
    label: str = DEFAULT_SECRET_LABEL
    version: str = DEFAULT_SECRET_VERSION


class SecretTokenService:
    """Create and restore simple reversible tokens such as ``<secret:1:...>``.

    The visible token format is deliberately compact and descriptive. The token
    body is ``salt.ciphertext`` where the salt is only used for password-based
    key derivation and the ciphertext is produced by the existing AES crypto
    primitive. No HTTP header or out-of-band state is needed to recognize tokens.
    """

    def __init__(
        self,
        *,
        crypto: TextCryptoService | None = None,
        label: str = DEFAULT_SECRET_LABEL,
        version: str = DEFAULT_SECRET_VERSION,
        accepted_tokens: Iterable[tuple[str, str]] | None = None,
    ) -> None:
        self._crypto = crypto or TextCryptoService()
        self.label = self._sanitize_part(label, DEFAULT_SECRET_LABEL)
        self.version = self._sanitize_part(version, DEFAULT_SECRET_VERSION)
        accepted = {(self.label, self.version), (DEFAULT_SECRET_LABEL, DEFAULT_SECRET_VERSION)}
        if accepted_tokens:
            accepted.update(
                (self._sanitize_part(label, DEFAULT_SECRET_LABEL), self._sanitize_part(version, DEFAULT_SECRET_VERSION))
                for label, version in accepted_tokens
            )
        self._accepted_tokens = frozenset(accepted)
        self._pattern = re.compile(
            rf"<{re.escape(self.label)}:{re.escape(self.version)}:{TOKEN_BODY_PATTERN}>"
        )

    @staticmethod
    def _sanitize_part(value: str, default: str) -> str:
        cleaned = (value or default).strip().lower()
        # Keep the visible token format simple and unambiguous.
        if not re.fullmatch(r"[a-z0-9_-]+", cleaned):
            return default
        return cleaned

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii")

    @staticmethod
    def _decode_bytes(value: str) -> bytes:
        try:
            return base64.urlsafe_b64decode(value.encode("ascii"))
        except Exception as exc:  # noqa: BLE001 - normalize base64 parsing for token callers
            raise TextCryptoError("secret token salt is invalid") from exc

    @staticmethod
    def derive_aes_key(password: str, salt: bytes) -> str:
        """Derive a 32-byte Presidio AES key from a password and per-token salt."""

        if not password:
            raise TextCryptoKeyError("privacy password is required")
        if not salt:
            raise TextCryptoKeyError("privacy token salt is required")
        derived = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,
            salt=salt,
            iterations=KDF_ITERATIONS,
        ).derive(password.encode("utf-8"))
        # 24 raw bytes encode to exactly 32 URL-safe ASCII bytes, satisfying
        # Presidio AES key length requirements without exposing raw bytes.
        return base64.urlsafe_b64encode(derived).decode("ascii")

    @property
    def token_prefix(self) -> str:
        return f"<{self.label}:{self.version}:"

    def _is_accepted(self, label: str, version: str) -> bool:
        return (label, version) in self._accepted_tokens

    def _iter_matches(self, text: str) -> list[re.Match[str]]:
        if not text:
            return []
        return [
            match
            for match in GENERIC_TOKEN_PATTERN.finditer(text)
            if self._is_accepted(match.group(1), match.group(2))
        ]

    def iter_tokens(self, text: str) -> list[SecretTokenMatch]:
        return [
            SecretTokenMatch(
                start=match.start(),
                end=match.end(),
                token=match.group(0),
                ciphertext=match.group(3),
                label=match.group(1),
                version=match.group(2),
            )
            for match in self._iter_matches(text)
        ]

    def contains_token(self, text: str) -> bool:
        return bool(self._iter_matches(text))

    def is_token(self, text: str) -> bool:
        if not text:
            return False
        match = GENERIC_TOKEN_PATTERN.fullmatch(text.strip())
        return bool(match and self._is_accepted(match.group(1), match.group(2)))

    @staticmethod
    def _split_body(body: str) -> tuple[bytes, str]:
        try:
            salt_text, ciphertext = body.split(".", 1)
        except ValueError as exc:
            raise TextCryptoError("secret token body is invalid") from exc
        if not salt_text or not ciphertext:
            raise TextCryptoError("secret token body is invalid")
        return SecretTokenService._decode_bytes(salt_text), ciphertext

    def encrypt_secret(self, plaintext: str, password: str) -> str:
        """Encrypt one complete secret value into a self-describing token.

        If the value is already a supported token, it is returned unchanged to
        make the operation idempotent.
        """

        if self.is_token(plaintext):
            return plaintext
        salt = os.urandom(SALT_BYTES)
        aes_key = self.derive_aes_key(password, salt)
        ciphertext = self._crypto.encrypt(plaintext, aes_key)
        return f"<{self.label}:{self.version}:{self._encode_bytes(salt)}.{ciphertext}>"

    def decrypt_token(self, token: str, password: str) -> str:
        match = GENERIC_TOKEN_PATTERN.fullmatch(token.strip())
        if not match or not self._is_accepted(match.group(1), match.group(2)):
            raise TextCryptoError("content is not a supported secret token")
        salt, ciphertext = self._split_body(match.group(3))
        aes_key = self.derive_aes_key(password, salt)
        return self._crypto.decrypt(ciphertext, aes_key)

    def restore_text(self, text: str, password: str) -> str:
        """Decrypt all supported secret tokens inside ``text``.

        Malformed strings such as ``<secret:1:example>`` are not considered
        tokens because valid token bodies must be ``salt.ciphertext``. Invalid
        ciphertext in a structurally valid token is treated as tampering and
        raises a normalized crypto error.
        """

        matches = self._iter_matches(text)
        if not matches:
            return text

        result = text
        for match in sorted(matches, key=lambda item: item.start(), reverse=True):
            plaintext = self.decrypt_token(match.group(0), password)
            result = f"{result[: match.start()]}{plaintext}{result[match.end() :]}"
        return result

    def strip_tokens(self, text: str, replacement: str = " ") -> str:
        """Replace token contents with whitespace for safe plaintext checks."""

        if not text:
            return text
        result = text
        for match in sorted(self._iter_matches(text), key=lambda item: item.start(), reverse=True):
            result = f"{result[: match.start()]}{replacement}{result[match.end() :]}"
        return result

    def replace_spans(
        self,
        text: str,
        spans: list[tuple[int, int]],
        password: str,
        *,
        should_encrypt: Callable[[str], bool] | None = None,
    ) -> str:
        """Encrypt non-overlapping spans in ``text`` from right to left."""

        if not spans:
            return text

        result = text
        for start, end in sorted(spans, key=lambda item: item[0], reverse=True):
            if start < 0 or end > len(result) or start >= end:
                continue
            value = result[start:end]
            if should_encrypt is not None and not should_encrypt(value):
                continue
            if self.is_token(value):
                continue
            result = f"{result[:start]}{self.encrypt_secret(value, password)}{result[end:]}"
        return result


__all__ = [
    "DEFAULT_SECRET_LABEL",
    "DEFAULT_SECRET_VERSION",
    "SecretTokenMatch",
    "SecretTokenService",
]
