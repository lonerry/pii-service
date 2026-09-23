"""Локальный NER (Natasha/Slovnet) для поиска персон по чанкам текста."""
from __future__ import annotations

import logging
import os
import threading
from functools import lru_cache

logger = logging.getLogger("pii.ner")

_MODE = os.getenv("PII_NER", "auto").lower()  # auto | on | off
_lock = threading.Lock()
_state: dict = {"loaded": False, "ok": False}


def _load() -> bool:
    if _state["loaded"]:
        return _state["ok"]
    with _lock:
        if _state["loaded"]:
            return _state["ok"]
        _state["loaded"] = True
        if _MODE == "off":
            return False
        try:
            from natasha import (  # type: ignore
                Doc,
                NewsEmbedding,
                NewsNERTagger,
                Segmenter,
            )

            emb = NewsEmbedding()
            _state.update(ok=True, Doc=Doc, seg=Segmenter(), ner=NewsNERTagger(emb))
            logger.info("natasha NER loaded")
        except Exception:  # noqa: BLE001
            logger.warning("natasha NER unavailable; slow path disabled")
            _state["ok"] = False
    return _state["ok"]


def available() -> bool:
    return _MODE != "off" and _load()


def warmup() -> None:
    if _MODE != "off":
        _load()
        if _state["ok"]:
            persons("Клиент Иванов Иван обратился в банк")


@lru_cache(maxsize=4096)
def persons(sentence: str) -> tuple[tuple[int, int], ...]:
    """PER-spans относительно sentence."""
    if not _load():
        return ()
    doc = _state["Doc"](sentence)
    doc.segment(_state["seg"])
    doc.tag_ner(_state["ner"])
    return tuple((s.start, s.stop) for s in doc.spans if s.type == "PER")
