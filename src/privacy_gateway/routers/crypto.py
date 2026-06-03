from fastapi import APIRouter, HTTPException, status

from privacy_gateway.schemas import CryptoEnvelope, PayloadType
from privacy_gateway.services.image_crypto import ImageCryptoError, ImageCryptoService
from privacy_gateway.services.presidio_crypto import TextCryptoKeyError, TextCryptoService

router = APIRouter(tags=["crypto"])
_text_crypto = TextCryptoService()
_image_crypto = ImageCryptoService()


def _with_content(payload: CryptoEnvelope, content: str) -> CryptoEnvelope:
    return CryptoEnvelope(type=payload.type, content=content, crypto_key=payload.crypto_key)


@router.post("/encrypt", response_model=CryptoEnvelope)
def encrypt(payload: CryptoEnvelope) -> CryptoEnvelope:
    if payload.type == PayloadType.TEXT:
        try:
            return _with_content(payload, _text_crypto.encrypt(payload.content, payload.crypto_key))
        except TextCryptoKeyError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if payload.type == PayloadType.IMAGE:
        try:
            return _with_content(payload, _image_crypto.encrypt(payload.content, payload.crypto_key))
        except ImageCryptoError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported type")


@router.post("/decrypt", response_model=CryptoEnvelope)
def decrypt(payload: CryptoEnvelope) -> CryptoEnvelope:
    if payload.type == PayloadType.TEXT:
        try:
            return _with_content(payload, _text_crypto.decrypt(payload.content, payload.crypto_key))
        except TextCryptoKeyError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - Presidio raises low-level crypto errors
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="content cannot be decrypted with provided crypto_key",
            ) from exc

    if payload.type == PayloadType.IMAGE:
        try:
            return _with_content(payload, _image_crypto.decrypt(payload.content, payload.crypto_key))
        except ImageCryptoError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported type")
