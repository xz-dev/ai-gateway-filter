from __future__ import annotations

"""Natural-language PII detection using prepared spaCy/Presidio plus fallback rules."""

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

try:  # pragma: no cover - import availability is covered by behavior tests
    import spacy
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import SpacyNlpEngine
except Exception:  # pragma: no cover - keep the library importable in minimal envs
    spacy = None  # type: ignore[assignment]
    AnalyzerEngine = None  # type: ignore[assignment]
    SpacyNlpEngine = object  # type: ignore[assignment,misc]

from privacy_gateway.services.privacy_tokens import SecretTokenService


logger = logging.getLogger(__name__)

DEFAULT_SPACY_MODEL = "en_core_web_sm"
FALLBACK_SPACY_MODELS = ("en_core_web_sm", "en_core_web_md", "en_core_web_lg")

PRESIDIO_ENTITY_TYPES = frozenset(
    {
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "CRYPTO",
        "IBAN_CODE",
        "IP_ADDRESS",
        "LOCATION",
        "NRP",
        "URL",
        "US_BANK_NUMBER",
        "US_DRIVER_LICENSE",
        "US_ITIN",
        "US_PASSPORT",
        "US_SSN",
    }
)
CUSTOM_REGEX_ENTITY_TYPES = frozenset({"CN_ID_CARD", "CN_PHONE_NUMBER", "SECRET_VALUE"})
DEFAULT_PII_ENTITIES = tuple(PRESIDIO_ENTITY_TYPES | CUSTOM_REGEX_ENTITY_TYPES)


@dataclass(frozen=True)
class PiiSpan:
    """Detected PII span in natural-language text."""

    start: int
    end: int
    entity_type: str
    score: float = 1.0

    @property
    def length(self) -> int:
        return self.end - self.start


class PreparedSpacyNlpEngine(SpacyNlpEngine):  # type: ignore[misc]
    """spaCy NLP engine which refuses runtime model downloads.

    Presidio's default ``SpacyNlpEngine`` downloads a missing spaCy model during
    ``load()``. Gateways should prepare the model before startup instead, so this
    subclass raises a clear error if the configured model is not installed.
    """

    @staticmethod
    def _download_spacy_model_if_needed(model_name: str) -> None:
        if spacy is None:
            raise ValueError("spaCy is not installed")
        if not (spacy.util.is_package(model_name) or Path(model_name).exists()):
            raise ValueError(
                f"spaCy model '{model_name}' is not installed; run "
                f"`python scripts/prepare_spacy_model.py {model_name}` before starting the gateway"
            )


def _is_spacy_model_available(model_name: str | None) -> bool:
    if not model_name or spacy is None:
        return False
    return bool(spacy.util.is_package(model_name) or Path(model_name).exists())


def _select_spacy_model(model_name: str | None, *, require_model: bool) -> str | None:
    wanted = model_name or DEFAULT_SPACY_MODEL
    if _is_spacy_model_available(wanted):
        return wanted

    if require_model:
        raise ValueError(
            f"spaCy model '{wanted}' is required but not installed; run "
            f"`python scripts/prepare_spacy_model.py {wanted}` before starting the gateway"
        )

    for fallback in FALLBACK_SPACY_MODELS:
        if fallback != wanted and _is_spacy_model_available(fallback):
            logger.warning("Configured spaCy model '%s' is unavailable; using prepared fallback '%s'", wanted, fallback)
            return fallback

    logger.warning(
        "No prepared spaCy model found for privacy detection; falling back to deterministic regex rules only. "
        "Run `python scripts/prepare_spacy_model.py %s` before starting the gateway to enable spaCy NER.",
        wanted,
    )
    return None


@lru_cache(maxsize=4)
def _cached_analyzer(model_name: str) -> object:
    if AnalyzerEngine is None:
        raise ValueError("presidio-analyzer is not installed")
    nlp_engine = PreparedSpacyNlpEngine(models=[{"lang_code": "en", "model_name": model_name}])
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])


class PiiDetectionService:
    """Detect PII spans in natural language text.

    The service uses Presidio Analyzer backed by a prepared spaCy model when the
    model is available. It never downloads models at request/runtime. If a model
    is unavailable and not required, deterministic fallback rules still cover
    common e-mail, phone, Chinese ID card, Chinese name/address, and secret-value
    patterns.

    This service deliberately operates on plain text. JSON parsing and choosing
    which fields to inspect belong to gateway code.
    """

    def __init__(
        self,
        *,
        entities: Iterable[str] = DEFAULT_PII_ENTITIES,
        score_threshold: float = 0.5,
        token_service: SecretTokenService | None = None,
        analyzer: object | None = None,
        spacy_model: str | None = DEFAULT_SPACY_MODEL,
        require_spacy_model: bool = False,
    ) -> None:
        self.entities = tuple(dict.fromkeys(entity.strip() for entity in entities if entity.strip()))
        self.score_threshold = float(score_threshold)
        self._token_service = token_service or SecretTokenService()
        self._analyzer = analyzer if analyzer is not None else self._build_analyzer(spacy_model, require_spacy_model)

    @staticmethod
    def _build_analyzer(spacy_model: str | None, require_spacy_model: bool) -> object | None:
        try:
            selected_model = _select_spacy_model(spacy_model, require_model=require_spacy_model)
            if selected_model is None:
                return None
            return _cached_analyzer(selected_model)
        except Exception:
            if require_spacy_model:
                raise
            logger.exception("Failed to initialize Presidio/spaCy analyzer; regex fallback remains enabled")
            return None

    @staticmethod
    def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
        return a_start < b_end and b_start < a_end

    def _token_ranges(self, text: str) -> list[tuple[int, int]]:
        return [(match.start, match.end) for match in self._token_service.iter_tokens(text)]

    def _is_inside_token(self, start: int, end: int, token_ranges: list[tuple[int, int]]) -> bool:
        return any(self._overlaps(start, end, token_start, token_end) for token_start, token_end in token_ranges)

    def _presidio_spans(self, text: str) -> list[PiiSpan]:
        if self._analyzer is None or not text:
            return []
        analyzer_entities = [entity for entity in self.entities if entity in PRESIDIO_ENTITY_TYPES]
        if not analyzer_entities:
            return []
        try:
            results = self._analyzer.analyze(  # type: ignore[attr-defined]
                text=text,
                language="en",
                entities=analyzer_entities,
                score_threshold=self.score_threshold,
            )
        except Exception as exc:
            logger.warning("Presidio analysis failed; continuing with deterministic regex rules: %s", exc)
            return []

        spans: list[PiiSpan] = []
        for result in results:
            start = int(getattr(result, "start", -1))
            end = int(getattr(result, "end", -1))
            entity_type = str(getattr(result, "entity_type", "PII"))
            score = float(getattr(result, "score", self.score_threshold))
            if 0 <= start < end <= len(text):
                spans.append(PiiSpan(start=start, end=end, entity_type=entity_type, score=score))
        return spans

    @staticmethod
    def _regex_spans(text: str) -> list[PiiSpan]:
        rules: list[tuple[str, re.Pattern[str], int, float]] = [
            (
                "EMAIL_ADDRESS",
                re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
                0,
                1.0,
            ),
            (
                "CN_ID_CARD",
                re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)"),
                0,
                1.0,
            ),
            (
                "CN_PHONE_NUMBER",
                re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"),
                0,
                0.95,
            ),
            (
                "SECRET_VALUE",
                re.compile(r"(?i)(?:password|passwd|pwd|api[_-]?key|secret|token)\s*(?:is|=|:|：)?\s*([^\s,;，。]+)"),
                1,
                0.95,
            ),
            (
                "SECRET_VALUE",
                re.compile(r"(?:密码|口令|密钥|令牌)\s*(?:是|为|=|:|：)?\s*([^\s,;，。]+)"),
                1,
                0.95,
            ),
            (
                "PERSON",
                re.compile(r"(?i)(?:my name is|name is|i am|i'm|call me)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})"),
                1,
                0.85,
            ),
            (
                "PERSON",
                re.compile(r"(?:我叫|我是|姓名是|名字是|联系人(?:是|为)?|姓名[:：]|名字[:：])\s*([\u4e00-\u9fff]{2,4})"),
                1,
                0.9,
            ),
            (
                "LOCATION",
                re.compile(r"(?:地址是|住在|位于|收货地址[:：]?|地址[:：]?)\s*([\u4e00-\u9fffA-Za-z0-9#\-—_\s]{4,80}(?:省|市|区|县|镇|乡|村|路|街|道|巷|弄|号)[\u4e00-\u9fffA-Za-z0-9#\-—_\s]{0,40})"),
                1,
                0.85,
            ),
            (
                "LOCATION",
                re.compile(r"(?i)(?:address is|live at|located at|ship to)\s+([A-Za-z0-9][A-Za-z0-9\s,.#-]{6,80})"),
                1,
                0.8,
            ),
        ]

        spans: list[PiiSpan] = []
        for entity_type, pattern, group, score in rules:
            for match in pattern.finditer(text):
                try:
                    start, end = match.span(group)
                except IndexError:
                    start, end = match.span(0)
                if start >= 0 and start < end:
                    spans.append(PiiSpan(start=start, end=end, entity_type=entity_type, score=score))
        return spans

    @classmethod
    def _dedupe(cls, spans: list[PiiSpan]) -> list[PiiSpan]:
        accepted: list[PiiSpan] = []
        # Prefer higher confidence and longer spans, then return text order.
        for span in sorted(spans, key=lambda item: (-item.score, -item.length, item.start)):
            if any(cls._overlaps(span.start, span.end, old.start, old.end) for old in accepted):
                continue
            accepted.append(span)
        return sorted(accepted, key=lambda item: item.start)

    def detect(self, text: str) -> list[PiiSpan]:
        if not text:
            return []

        token_ranges = self._token_ranges(text)
        allowed_entities = set(self.entities)
        spans = [*self._presidio_spans(text), *self._regex_spans(text)]
        spans = [span for span in spans if span.entity_type in allowed_entities]
        spans = [
            span
            for span in spans
            if span.score >= self.score_threshold and not self._is_inside_token(span.start, span.end, token_ranges)
        ]
        return self._dedupe(spans)


__all__ = [
    "DEFAULT_PII_ENTITIES",
    "DEFAULT_SPACY_MODEL",
    "PiiDetectionService",
    "PRESIDIO_ENTITY_TYPES",
    "PiiSpan",
    "PreparedSpacyNlpEngine",
]
