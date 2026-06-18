#!/usr/bin/env python
from __future__ import annotations

"""Prepare the spaCy model required by privacy-gateway before runtime.

Usage:
    python scripts/prepare_spacy_model.py [model-name]

The default model is en_core_web_sm. This script intentionally performs the
network/download step during build or deployment preparation so gateway startup
and request handling never download models implicitly.
"""

import sys
from pathlib import Path

import spacy
from spacy.cli import download

DEFAULT_MODEL = "en_core_web_sm"


def model_is_available(model_name: str) -> bool:
    return bool(spacy.util.is_package(model_name) or Path(model_name).exists())


def main() -> int:
    model_name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    if model_is_available(model_name):
        print(f"spaCy model already available: {model_name}")
        return 0

    print(f"Downloading spaCy model: {model_name}")
    download(model_name)
    if not model_is_available(model_name):
        print(f"Failed to prepare spaCy model: {model_name}", file=sys.stderr)
        return 1
    print(f"spaCy model prepared: {model_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
