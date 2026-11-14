"""Shared loaders for the small reference data files under data/.

Kept in one place so every module (headers, links, domains, scoring)
resolves the data/ directory the same way regardless of cwd.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _read_lines(filename: str) -> list[str]:
    path = os.path.join(_DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as fp:
        return [
            line.strip().lower() for line in fp if line.strip() and not line.strip().startswith("#")
        ]


@lru_cache(maxsize=1)
def load_brand_domains() -> list[str]:
    return _read_lines("brands.txt")


@lru_cache(maxsize=1)
def load_shortener_domains() -> set[str]:
    return set(_read_lines("shorteners.txt"))


@lru_cache(maxsize=1)
def load_scoring_weights() -> dict:
    path = os.path.join(_DATA_DIR, "scoring_weights.json")
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)
