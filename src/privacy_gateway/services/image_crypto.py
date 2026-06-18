from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Iterable, Protocol

from cryptography.fernet import Fernet, InvalidToken
from PIL import Image, ImageDraw, PngImagePlugin, UnidentifiedImageError

from privacy_gateway.errors import ImageCryptoError
from privacy_gateway.services.pii_detection import (
    CUSTOM_REGEX_ENTITY_TYPES,
    DEFAULT_SPACY_MODEL,
    PRESIDIO_ENTITY_TYPES,
    PiiDetectionService,
)


logger = logging.getLogger(__name__)

IMAGE_REGION_METADATA_KEY = "privacy_gateway_image_regions_v1"
DEFAULT_IMAGE_REGION_CACHE_SIZE = 1000
FALLBACK_MAX_REGION_SIDE = 64


@dataclass(frozen=True)
class ImageRegion:
    """Pixel rectangle to protect inside an image.

    Coordinates use Pillow's standard half-open box semantics:
    ``left <= x < right`` and ``top <= y < bottom``.
    """

    left: int
    top: int
    right: int
    bottom: int

    @classmethod
    def from_xywh(cls, x: int, y: int, width: int, height: int) -> "ImageRegion":
        return cls(left=x, top=y, right=x + width, bottom=y + height)

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    def clamp(self, image_width: int, image_height: int) -> "ImageRegion | None":
        left = min(max(int(self.left), 0), image_width)
        top = min(max(int(self.top), 0), image_height)
        right = min(max(int(self.right), 0), image_width)
        bottom = min(max(int(self.bottom), 0), image_height)
        if right <= left or bottom <= top:
            return None
        return ImageRegion(left=left, top=top, right=right, bottom=bottom)

    def as_box(self) -> tuple[int, int, int, int]:
        return (self.left, self.top, self.right, self.bottom)


class ImageRegionDetector(Protocol):
    """Protocol for image PII region detectors."""

    def detect(self, image: Image.Image) -> list[ImageRegion]:
        """Return image regions that should be protected."""


class PresidioImageRegionDetector:
    """Detect image PII regions with Microsoft Presidio Image Redactor.

    Presidio's image package performs OCR and returns bounding boxes for PII
    text. This wrapper keeps the core image crypto code independent from a
    specific result object shape and raises ``ImageCryptoError`` if OCR analysis
    fails at runtime.
    """

    def __init__(
        self,
        analyzer: object | None = None,
        *,
        text_analyzer: object | None = None,
        spacy_model: str | None = DEFAULT_SPACY_MODEL,
        require_spacy_model: bool = False,
        entities: Iterable[str] | None = None,
        score_threshold: float = 0.5,
    ) -> None:
        if analyzer is None:
            from presidio_image_redactor import ImageAnalyzerEngine

            if text_analyzer is None:
                detector_kwargs: dict[str, object] = {
                    "spacy_model": spacy_model,
                    "require_spacy_model": require_spacy_model,
                    "score_threshold": score_threshold,
                }
                if entities is not None:
                    detector_kwargs["entities"] = tuple(entities)
                text_analyzer = PiiDetectionService(**detector_kwargs).presidio_analyzer
            analyzer = ImageAnalyzerEngine(analyzer_engine=text_analyzer) if text_analyzer is not None else None
        self._analyzer = analyzer
        self._entities = None if entities is None else tuple(dict.fromkeys(entities))
        self._score_threshold = float(score_threshold)
        self._ad_hoc_recognizers = self._build_ad_hoc_recognizers(self._entities)

    @staticmethod
    def _build_ad_hoc_recognizers(entities: Iterable[str] | None) -> list[object]:
        if entities is None:
            return []
        enabled = set(entities) & CUSTOM_REGEX_ENTITY_TYPES
        if not enabled:
            return []

        from presidio_analyzer import Pattern, PatternRecognizer

        recognizers: list[object] = []
        if "CN_ID_CARD" in enabled:
            recognizers.append(
                PatternRecognizer(
                    supported_entity="CN_ID_CARD",
                    name="privacy-gateway-cn-id-card-image",
                    patterns=[
                        Pattern(
                            name="cn_id_card",
                            regex=r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)",
                            score=1.0,
                        )
                    ],
                )
            )
        if "CN_PHONE_NUMBER" in enabled:
            recognizers.append(
                PatternRecognizer(
                    supported_entity="CN_PHONE_NUMBER",
                    name="privacy-gateway-cn-phone-image",
                    patterns=[
                        Pattern(
                            name="cn_phone_number",
                            regex=r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)",
                            score=0.95,
                        )
                    ],
                )
            )
        if "SECRET_VALUE" in enabled:
            recognizers.append(
                PatternRecognizer(
                    supported_entity="SECRET_VALUE",
                    name="privacy-gateway-secret-value-image",
                    patterns=[
                        Pattern(
                            name="latin_secret_value",
                            regex=r"(?i)(?:password|passwd|pwd|api[_-]?key|secret|token)\s*(?:is|=|:|：)?\s*[^\s,;，。]+",
                            score=0.95,
                        ),
                        Pattern(
                            name="cjk_secret_value",
                            regex=r"(?:密码|口令|密钥|令牌)\s*(?:是|为|=|:|：)?\s*[^\s,;，。]+",
                            score=0.95,
                        ),
                    ],
                )
            )
        return recognizers

    def _analyze(self, image: Image.Image) -> object:
        analyzer = self._analyzer
        if analyzer is None:
            raise ImageCryptoError("image PII region detection is unavailable")
        analyze = getattr(analyzer, "analyze")
        kwargs: dict[str, object] = {"score_threshold": self._score_threshold}
        if self._entities is not None:
            presidio_entities = [entity for entity in self._entities if entity in PRESIDIO_ENTITY_TYPES]
            custom_entities = [entity for entity in self._entities if entity in CUSTOM_REGEX_ENTITY_TYPES]
            analyzer_entities = [*presidio_entities, *custom_entities]
            if not analyzer_entities:
                return []
            kwargs["entities"] = analyzer_entities
        if self._ad_hoc_recognizers:
            kwargs["ad_hoc_recognizers"] = self._ad_hoc_recognizers
        return analyze(image=image, **kwargs)

    @staticmethod
    def _get_value(candidate: object, *names: str) -> object | None:
        for name in names:
            if isinstance(candidate, dict) and name in candidate:
                return candidate[name]
            value = getattr(candidate, name, None)
            if value is not None:
                return value
        return None

    @classmethod
    def _region_from_candidate(cls, candidate: object) -> ImageRegion | None:
        is_pii = cls._get_value(candidate, "is_PII", "is_pii")
        if is_pii is False:
            return None

        left = cls._get_value(candidate, "left", "x")
        top = cls._get_value(candidate, "top", "y")
        width = cls._get_value(candidate, "width")
        height = cls._get_value(candidate, "height")
        right = cls._get_value(candidate, "right")
        bottom = cls._get_value(candidate, "bottom")

        try:
            if left is not None and top is not None and width is not None and height is not None:
                return ImageRegion.from_xywh(int(left), int(top), int(width), int(height))
            if left is not None and top is not None and right is not None and bottom is not None:
                return ImageRegion(int(left), int(top), int(right), int(bottom))
        except (TypeError, ValueError):
            return None
        return None

    @classmethod
    def _collect_regions(cls, value: object, *, seen: set[int] | None = None) -> list[ImageRegion]:
        if seen is None:
            seen = set()
        value_id = id(value)
        if value_id in seen:
            return []
        seen.add(value_id)

        region = cls._region_from_candidate(value)
        regions = [region] if region is not None else []

        if isinstance(value, dict):
            children = value.values()
        elif isinstance(value, (list, tuple, set)):
            children = value
        else:
            children = []
            for attr in ("bounding_boxes", "bboxes", "ocr_results", "results", "items"):
                child = getattr(value, attr, None)
                if child is not None:
                    children.append(child)

        for child in children:
            regions.extend(cls._collect_regions(child, seen=seen))
        return regions

    def detect(self, image: Image.Image) -> list[ImageRegion]:
        try:
            return self._collect_regions(self._analyze(image))
        except ImageCryptoError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalize OCR/runtime failures for API callers
            logger.warning("Presidio image region detection failed: %s", exc)
            raise ImageCryptoError("image PII region detection failed") from exc


class _RegionCryptoCache:
    """Small process-local LRU cache for full-quality encrypted image regions."""

    def __init__(self, max_entries: int = DEFAULT_IMAGE_REGION_CACHE_SIZE) -> None:
        self.max_entries = max(int(max_entries), 1)
        self._items: OrderedDict[str, bytes] = OrderedDict()
        self._lock = RLock()

    def put(self, region_hash: str, encrypted_region: bytes) -> None:
        with self._lock:
            self._items[region_hash] = encrypted_region
            self._items.move_to_end(region_hash)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def get(self, region_hash: str) -> bytes | None:
        with self._lock:
            encrypted_region = self._items.get(region_hash)
            if encrypted_region is None:
                return None
            self._items.move_to_end(region_hash)
            return encrypted_region

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class ImageCryptoService:
    """Automatically protect detected sensitive image regions.

    The service does not expose or perform whole-image encryption. It analyzes
    the image, protects only detected sensitive pixel regions, and leaves the
    rest of the image viewable. Each protected region is replaced by a redaction
    rectangle in the returned PNG image while the original region is encrypted
    and stored in a process-local LRU cache keyed by SHA-256 hash.

    A low-resolution encrypted fallback for each region is embedded in PNG
    metadata. Decryption restores the full-quality region when the hash is still
    present in the cache; otherwise it restores the embedded low-resolution
    fallback and scales it back to the original rectangle size.
    """

    _shared_cache = _RegionCryptoCache(DEFAULT_IMAGE_REGION_CACHE_SIZE)

    def __init__(
        self,
        *,
        detector: ImageRegionDetector | None = None,
        cache: _RegionCryptoCache | None = None,
        text_analyzer: object | None = None,
        spacy_model: str | None = DEFAULT_SPACY_MODEL,
        require_spacy_model: bool = False,
        entities: Iterable[str] | None = None,
        score_threshold: float = 0.5,
    ) -> None:
        # Keep OCR/ImageAnalyzer construction lazy so text-only filters do not
        # pay image startup cost and do not require OCR binaries until an image
        # actually needs protection.
        self._detector = detector
        self._detector_lock = RLock()
        self._detector_kwargs = {
            "text_analyzer": text_analyzer,
            "spacy_model": spacy_model,
            "require_spacy_model": require_spacy_model,
            "entities": tuple(entities) if entities is not None else None,
            "score_threshold": score_threshold,
        }
        self._cache = cache or self._shared_cache

    def _get_detector(self) -> ImageRegionDetector:
        if self._detector is None:
            with self._detector_lock:
                if self._detector is None:
                    self._detector = PresidioImageRegionDetector(**self._detector_kwargs)
        return self._detector

    @staticmethod
    def _fernet(crypto_key: str) -> Fernet:
        digest = hashlib.sha256(crypto_key.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    @staticmethod
    def _decode_base64_image(content: str) -> Image.Image:
        try:
            image_bytes = base64.b64decode(content, validate=True)
        except Exception as exc:  # noqa: BLE001 - normalize base64 errors for API layer
            raise ImageCryptoError("content must be a valid base64 image string") from exc

        try:
            image = Image.open(io.BytesIO(image_bytes))
            image.load()
        except UnidentifiedImageError as exc:
            raise ImageCryptoError("content must be a valid base64 image string") from exc
        except Exception as exc:  # noqa: BLE001 - normalize image parsing errors for API layer
            raise ImageCryptoError("content must be a valid base64 image string") from exc
        return image

    @staticmethod
    def _image_to_png_bytes(image: Image.Image, *, metadata: dict[str, object] | None = None) -> bytes:
        output = io.BytesIO()
        png_info = None
        if metadata:
            png_info = PngImagePlugin.PngInfo()
            png_info.add_text(IMAGE_REGION_METADATA_KEY, json.dumps(metadata, separators=(",", ":")))
        image.save(output, format="PNG", pnginfo=png_info)
        return output.getvalue()

    @classmethod
    def _image_to_base64_png(cls, image: Image.Image, *, metadata: dict[str, object] | None = None) -> str:
        return base64.b64encode(cls._image_to_png_bytes(image, metadata=metadata)).decode("ascii")

    @staticmethod
    def _fallback_region(crop: Image.Image) -> Image.Image:
        fallback = crop.copy()
        longest = max(fallback.size)
        if longest <= FALLBACK_MAX_REGION_SIDE:
            return fallback
        scale = FALLBACK_MAX_REGION_SIDE / float(longest)
        size = (max(int(fallback.width * scale), 1), max(int(fallback.height * scale), 1))
        return fallback.resize(size, Image.Resampling.BICUBIC)

    @staticmethod
    def _region_hash(encrypted_region: bytes) -> str:
        return hashlib.sha256(encrypted_region).hexdigest()

    @staticmethod
    def _draw_redaction(image: Image.Image, region: ImageRegion, region_hash: str) -> None:
        draw = ImageDraw.Draw(image)
        box = (region.left, region.top, region.right - 1, region.bottom - 1)
        # Neutral visible placeholder. The hash suffix helps humans correlate
        # logs/metadata without exposing original image content. Pillow drawing
        # rectangles are inclusive, so use right-1/bottom-1 to match crop boxes.
        draw.rectangle(box, fill=(24, 24, 24), outline=(230, 230, 230), width=1)
        if region.width >= 56 and region.height >= 18:
            draw.text((region.left + 3, region.top + 3), region_hash[:10], fill=(230, 230, 230))

    @staticmethod
    def _open_png_metadata(image: Image.Image) -> dict[str, object] | None:
        raw = image.info.get(IMAGE_REGION_METADATA_KEY)
        if not raw:
            return None
        try:
            metadata = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ImageCryptoError("partial image encryption metadata is invalid") from exc
        if not isinstance(metadata, dict) or metadata.get("version") != 1:
            raise ImageCryptoError("partial image encryption metadata is invalid")
        return metadata

    def encrypt(self, content: str, crypto_key: str) -> str:
        """Automatically detect and protect sensitive image regions."""

        image = self._decode_base64_image(content).convert("RGBA")
        try:
            detected_regions = self._get_detector().detect(image)
        except ImageCryptoError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalize detector failures for API callers
            raise ImageCryptoError("image PII region detection failed") from exc
        regions = [region.clamp(*image.size) for region in detected_regions]
        regions_to_encrypt = [region for region in regions if region is not None]
        if not regions_to_encrypt:
            # No sensitive image regions were detected; preserve the input image.
            return content
        return self._protect_regions(image, crypto_key, regions_to_encrypt)

    def decrypt(self, content: str, crypto_key: str) -> str:
        """Restore a partially protected image using metadata/cache entries."""

        return self.decrypt_regions(content, crypto_key)

    def _protect_regions(self, image: Image.Image, crypto_key: str, regions: Iterable[ImageRegion]) -> str:
        fernet = self._fernet(crypto_key)
        metadata_regions: list[dict[str, object]] = []
        protected = image.copy()

        for region in regions:
            crop = image.crop(region.as_box())
            full_region_png = self._image_to_png_bytes(crop)
            encrypted_full_region = fernet.encrypt(full_region_png)
            region_hash = self._region_hash(encrypted_full_region)
            self._cache.put(region_hash, encrypted_full_region)

            fallback_region = self._fallback_region(crop)
            fallback_png = self._image_to_png_bytes(fallback_region)
            encrypted_fallback = fernet.encrypt(fallback_png)

            metadata_regions.append(
                {
                    "box": [region.left, region.top, region.right, region.bottom],
                    "hash": region_hash,
                    "fallback": base64.b64encode(encrypted_fallback).decode("ascii"),
                }
            )
            self._draw_redaction(protected, region, region_hash)

        metadata: dict[str, object] = {
            "version": 1,
            "regions": metadata_regions,
        }
        return self._image_to_base64_png(protected, metadata=metadata)

    def _decrypt_region_png(self, encrypted_region: bytes, crypto_key: str) -> Image.Image:
        try:
            region_png = self._fernet(crypto_key).decrypt(encrypted_region)
            region = Image.open(io.BytesIO(region_png))
            region.load()
        except InvalidToken as exc:
            raise ImageCryptoError("content cannot be decrypted with provided crypto_key") from exc
        except Exception as exc:  # noqa: BLE001 - normalize image parsing errors for API layer
            raise ImageCryptoError("partial image encrypted region is invalid") from exc
        return region.convert("RGBA")

    def decrypt_regions(self, content: str, crypto_key: str) -> str:
        """Restore redacted regions from the LRU cache or embedded fallback."""

        image = self._decode_base64_image(content).convert("RGBA")
        metadata = self._open_png_metadata(image)
        if metadata is None:
            return content

        raw_regions = metadata.get("regions")
        if not isinstance(raw_regions, list):
            raise ImageCryptoError("partial image encryption metadata is invalid")

        restored = image.copy()
        for item in raw_regions:
            if not isinstance(item, dict):
                raise ImageCryptoError("partial image encryption metadata is invalid")
            try:
                box = item["box"]
                region_hash = str(item["hash"])
                fallback = str(item["fallback"])
                left, top, right, bottom = [int(value) for value in box]
            except Exception as exc:  # noqa: BLE001 - normalize metadata shape errors
                raise ImageCryptoError("partial image encryption metadata is invalid") from exc

            region = ImageRegion(left=left, top=top, right=right, bottom=bottom).clamp(*restored.size)
            if region is None:
                continue

            encrypted_region = self._cache.get(region_hash)
            if encrypted_region is None:
                try:
                    encrypted_region = base64.b64decode(fallback, validate=True)
                except Exception as exc:  # noqa: BLE001 - normalize fallback parsing errors
                    raise ImageCryptoError("partial image encrypted fallback is invalid") from exc

            patch = self._decrypt_region_png(encrypted_region, crypto_key)
            if patch.size != (region.width, region.height):
                patch = patch.resize((region.width, region.height), Image.Resampling.BICUBIC)
            restored.paste(patch, region.as_box())

        return self._image_to_base64_png(restored)

    def cache_size(self) -> int:
        return len(self._cache)


__all__ = [
    "DEFAULT_IMAGE_REGION_CACHE_SIZE",
    "IMAGE_REGION_METADATA_KEY",
    "ImageCryptoService",
    "ImageRegion",
    "ImageRegionDetector",
    "PresidioImageRegionDetector",
]
