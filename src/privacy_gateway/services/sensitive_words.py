import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SensitiveMatch:
    detected_word: str
    type: str = "Prompt Injection"


class SensitiveWordService:
    """Case-insensitive phrase matcher for AI-abuse prevention."""

    def __init__(self, phrases: list[str]) -> None:
        self._phrases = [phrase.casefold() for phrase in phrases]
        self._compact_phrases = {
            phrase: re.sub(r"\s+", "", phrase) for phrase in self._phrases
        }
        self._original = {phrase.casefold(): phrase for phrase in phrases}

    def find(self, text: str) -> SensitiveMatch | None:
        haystack = text.casefold()
        compact_haystack = re.sub(r"\s+", "", haystack)
        positions: list[tuple[int, str]] = []

        for phrase in self._phrases:
            index = haystack.find(phrase)
            if index >= 0:
                positions.append((index, phrase))
                continue

            compact_index = compact_haystack.find(self._compact_phrases[phrase])
            if compact_index >= 0:
                positions.append((compact_index, phrase))

        if not positions:
            return None

        _, phrase = min(positions, key=lambda item: item[0])
        return SensitiveMatch(detected_word=self._original[phrase])
