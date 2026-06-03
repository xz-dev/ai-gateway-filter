from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from privacy_gateway.config import Settings, get_settings
from privacy_gateway.schemas import SensitiveOkResponse, SensitiveTextRequest
from privacy_gateway.services.sensitive_words import SensitiveMatch, SensitiveWordService

router = APIRouter(prefix="/sensitive-words", tags=["sensitive-words"])


def _service(settings: Settings = Depends(get_settings)) -> SensitiveWordService:
    return SensitiveWordService(settings.prompt_injection_phrases)


def _match_response(match: SensitiveMatch) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detected_word": match.detected_word, "type": match.type},
    )


@router.post("/text", response_model=SensitiveOkResponse)
def check_text(
    payload: SensitiveTextRequest,
    service: SensitiveWordService = Depends(_service),
) -> SensitiveOkResponse | JSONResponse:
    match = service.find(payload.text)
    if match:
        return _match_response(match)
    return SensitiveOkResponse()


@router.post("/text/stream", response_model=SensitiveOkResponse)
async def check_text_stream(
    request: Request,
    settings: Settings = Depends(get_settings),
    service: SensitiveWordService = Depends(_service),
) -> SensitiveOkResponse | JSONResponse:
    buffer = ""
    max_window = max(settings.max_sensitive_stream_window, 1)

    async for chunk in request.stream():
        if not chunk:
            continue
        buffer += chunk.decode("utf-8", errors="ignore")
        if len(buffer) > max_window:
            buffer = buffer[-max_window:]

        match = service.find(buffer)
        if match:
            return _match_response(match)

    return SensitiveOkResponse()
