from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class PayloadType(StrEnum):
    TEXT = "text"
    IMAGE = "image"


class CryptoEnvelope(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    type: PayloadType
    content: str = Field(..., min_length=1)
    crypto_key: str = Field(..., min_length=1)


class SensitiveTextRequest(BaseModel):
    text: str


class SensitiveMatchResponse(BaseModel):
    detected_word: str
    type: str = "Prompt Injection"


class SensitiveOkResponse(BaseModel):
    ok: bool = True
