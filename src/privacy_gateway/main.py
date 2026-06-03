import uvicorn
from fastapi import FastAPI

from privacy_gateway.routers.crypto import router as crypto_router
from privacy_gateway.routers.sensitive_words import router as sensitive_words_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Privacy Gateway",
        description="FastAPI wrapper for crypto payload protection and AI-abuse sensitive-word checks.",
        version="0.1.0",
    )
    app.include_router(crypto_router)
    app.include_router(sensitive_words_router)
    return app


app = create_app()


def main() -> None:
    uvicorn.run("privacy_gateway.main:app", host="127.0.0.1", port=8000, reload=False)
