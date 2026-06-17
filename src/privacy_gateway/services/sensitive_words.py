from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class SensitiveMatch:
    detected_word: str
    type: str = "Prompt Injection"


class SensitiveWordService:
    """Case-insensitive phrase detector for sensitive phrases."""

    def __init__(self, phrases: Sequence[str]):
        normalized = [phrase.strip() for phrase in phrases if isinstance(phrase, str)]
        self._phrases = [phrase.casefold() for phrase in normalized if phrase]
        self._compact_phrases = {phrase: re.sub(r"\s+", "", phrase) for phrase in self._phrases}
        self._original = {phrase.casefold(): phrase for phrase in self._phrases}

    def find(self, text: str) -> SensitiveMatch | None:
        if not self._phrases:
            return None

        haystack = text.casefold()
        compact_haystack = re.sub(r"\s+", "", haystack)

        best_index = None
        best_phrase = None

        for phrase in self._phrases:
            index = haystack.find(phrase)
            if index >= 0 and (best_index is None or index < best_index):
                best_index = index
                best_phrase = phrase

            compact_phrase = self._compact_phrases[phrase]
            compact_index = compact_haystack.find(compact_phrase)
            if compact_index >= 0 and (best_index is None or compact_index < best_index):
                best_index = compact_index
                best_phrase = phrase

        if best_phrase is None:
            return None

        return SensitiveMatch(detected_word=self._original[best_phrase])
