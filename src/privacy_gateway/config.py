from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_PROMPT_INJECTION_PHRASES = (
    "ignore previous instructions",
    "reveal your system prompt",
    "bypass policy",
    "disregard all prior guidance",
    "repeat the exact instructions",
    "hidden instructions",
    "developer debugging mode",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PRIVACY_GATEWAY_", env_file=".env")

    sensitive_phrases: str = ",".join(DEFAULT_PROMPT_INJECTION_PHRASES)
    max_sensitive_stream_window: int = 4096

    @property
    def prompt_injection_phrases(self) -> list[str]:
        return [phrase.strip() for phrase in self.sensitive_phrases.split(",") if phrase.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
