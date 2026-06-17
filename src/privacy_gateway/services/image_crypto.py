from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from privacy_gateway.errors import ImageCryptoError


class ImageCryptoService:
    """Encrypt/decrypt image bytes carried as base64 strings."""

    @staticmethod
    def _fernet(crypto_key: str) -> Fernet:
        digest = hashlib.sha256(crypto_key.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, content: str, crypto_key: str) -> str:
        try:
            image_bytes = base64.b64decode(content, validate=True)
        except Exception as exc:  # noqa: BLE001 - normalize base64 errors for API layer
            raise ImageCryptoError("content must be a valid base64 image string") from exc

        encrypted = self._fernet(crypto_key).encrypt(image_bytes)
        return base64.b64encode(encrypted).decode("ascii")

    def decrypt(self, content: str, crypto_key: str) -> str:
        try:
            encrypted = base64.b64decode(content, validate=True)
            image_bytes = self._fernet(crypto_key).decrypt(encrypted)
        except InvalidToken as exc:
            raise ImageCryptoError("content cannot be decrypted with provided crypto_key") from exc
        except Exception as exc:  # noqa: BLE001 - normalize base64 errors for API layer
            raise ImageCryptoError("content must be a valid encrypted base64 image string") from exc

        return base64.b64encode(image_bytes).decode("ascii")
