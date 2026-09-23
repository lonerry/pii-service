"""Оркестрация: Structure → Detectors → Span Resolver → Context/Owner → Policy.

FAST PATH (всегда): regex + validators + структура + словари + hotword rules.
NER (natasha) — локальная модель, ~1мс на предложение / ~15мс на 3500 симв. текста,
поэтому запускается по всему тексту (чанками, как и остальные детекторы), а не только
на узких «неоднозначных» окнах — запас по времени огромный (бюджет ~2-3с на запрос).
Большие тексты обрабатываются чанками с сохранением абсолютных offset-ов.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterable

from ..observability import span
from . import context, ner
from .candidates import MASK, Candidate, SpanIndex
from .detectors import REGISTRY, detect_field_values
from .normalize import normalize_text
from .policy import DEFAULT_POLICY, Policy
from .profiles import is_present
from .resolver import dedupe, select
from .structure import FieldIndex, parse_fields

logger = logging.getLogger("pii.pipeline")

CHUNK_SIZE = int(os.getenv("PII_CHUNK_SIZE", "20000"))


def chunks(text: str, size: int = CHUNK_SIZE) -> Iterable[tuple[int, int]]:
    """Границы чанков по переводу строки / концу предложения — сущности не режутся."""
    n = len(text)
    pos = 0
    while pos < n:
        end = min(n, pos + size)
        if end < n:
            cut = text.rfind("\n", pos + size // 2, end)
            if cut < 0:
                cut = text.rfind(". ", pos + size // 2, end)
            if cut < 0:
                cut = text.rfind(" ", pos + size // 2, end)
            if cut > pos:
                end = cut + 1
        yield pos, end
        pos = end


def _chunk_text(text: str) -> Iterable[tuple[int, str]]:
    """Единый обход чанков с их абсолютным смещением."""
    for lo, hi in chunks(text):
        yield lo, text[lo:hi] if (lo, hi) != (0, len(text)) else text


def _detect(text: str, enabled: set[str]) -> list[Candidate]:
    out: list[Candidate] = []
    for lo, part in _chunk_text(text):
        for candidate in REGISTRY.collect(part, enabled):
            if lo:
                candidate.start += lo
                candidate.end += lo
                candidate.anchor += lo
            out.append(candidate)
    return out


def _ner_candidates(text: str, cands: list[Candidate]) -> list[Candidate]:
    """NER по всему тексту чанками (не только «неоднозначным» окнам — natasha быстрая
    настолько, что можно себе это позволить всегда). PER-спаны, уже покрытые
    FAST-детекторами (FIO/CARDHOLDER/ADDRESS), пропускаются — не дублируем работу."""
    covered = SpanIndex((c.start, c.end) for c in cands if c.etype in ("FIO", "CARDHOLDER", "ADDRESS"))
    out: list[Candidate] = []
    for lo, part in _chunk_text(text):
        for s, e in ner.persons(part):
            abs_s, abs_e = lo + s, lo + e
            if covered.overlaps(abs_s, abs_e):
                continue
            out.append(Candidate(abs_s, abs_e, "FIO", text[abs_s:abs_e], 0.75, "natasha_ner"))
    return out


_MIN_LINK_LEN = 3


def _propagate_values(text: str, cands: list[Candidate]) -> list[Candidate]:
    """Если значение уже признано sensitive (MASK), маскировать его повторения в тексте."""
    index = SpanIndex((c.start, c.end) for c in cands)
    seen: dict = {}
    for c in cands:
        if c.action != MASK or len(c.text) < _MIN_LINK_LEN:
            continue
        seen.setdefault((c.etype, c.text), c)
    extra: list[Candidate] = []
    for (etype, value), proto in seen.items():
        start = 0
        while True:
            idx = text.find(value, start)
            if idx < 0:
                break
            end = idx + len(value)
            start = idx + 1
            if index.overlaps(idx, end):
                continue
            nc = Candidate(idx, end, etype, value, proto.score, "value_link",
                           owner=proto.owner, role=proto.role, labeled=proto.labeled)
            nc.action = MASK
            nc.signals.append("value_link")
            extra.append(nc)
            index.add(idx, end)
    return extra


def _evaluated_candidates(text: str, enabled: Iterable[str], policy: Policy,
                          use_ner: bool) -> list[Candidate]:
    """Общий путь обнаружения и принятия решений для analyze и explain."""
    enabled = set(enabled)
    with span("pii.structure"):
        fields = parse_fields(text)
        index = FieldIndex(fields) if fields else None
    with span("pii.fast_detection"):
        cands = _detect(text, enabled)
        if fields:
            cands.extend(
                candidate
                for candidate in detect_field_values(text, fields)
                if candidate.etype in enabled
            )
    if use_ner and "FIO" in enabled and ner.available():
        with span("pii.ner"):
            cands.extend(_ner_candidates(text, cands))
    with span("pii.context_policy"):
        cands = dedupe(cands)
        context.resolve(text, cands, index)
        present_types = frozenset(
            candidate.etype
            for candidate in cands
            if is_present(candidate, policy.detection_profile)
        )
        for c in cands:
            c.action, reason = policy.decide(c, enabled, present_types)
            c.signals.append(reason)
    return cands


def analyze_for_masking(
    text: str,
    enabled: Iterable[str],
    policy: Policy = DEFAULT_POLICY,
    use_ner: bool | None = None,
) -> tuple[list[Candidate], list[Candidate]]:
    """Вернуть выбранные MASK-кандидаты и все решения контекстной политики."""
    with span("pii.pipeline"):
        view = normalize_text(text)
        decisions = _evaluated_candidates(view, enabled, policy, use_ner is not False)
        with span("pii.resolve_spans"):
            candidates = decisions + _propagate_values(view, decisions)
            selected = select(view, candidates)
            for candidate in selected:
                candidate.text = text[candidate.start:candidate.end]
            return selected, decisions


def analyze(
    text: str,
    enabled: Iterable[str],
    policy: Policy = DEFAULT_POLICY,
    use_ner: bool | None = None,
) -> list[Candidate]:
    """Вернуть итоговые непересекающиеся кандидаты с action == MASK."""
    selected, _ = analyze_for_masking(text, enabled, policy, use_ner)
    return selected


def evaluate(
    text: str,
    enabled: Iterable[str],
    policy: Policy = DEFAULT_POLICY,
    *,
    use_ner: bool = False,
) -> list[Candidate]:
    """Collect and apply context/policy without overlap or value propagation."""
    return _evaluated_candidates(
        normalize_text(text), enabled, policy, use_ner=use_ner
    )


def explain(text: str, enabled: Iterable[str]) -> list[dict]:
    """Отладка без исходных значений: только тип, span, owner/role, score, action."""
    cands = _evaluated_candidates(normalize_text(text), enabled, DEFAULT_POLICY, use_ner=False)
    out = []
    for c in sorted(cands, key=lambda c: c.start):
        out.append({"type": c.etype, "start": c.start, "end": c.end, "owner": c.owner, "role": c.role,
                    "score": round(c.score, 2), "effective_score": round(c.effective_score, 2),
                    "evidence": {k: round(v, 2) for k, v in c.evidence.items()},
                    "source": c.source, "action": c.action, "reason": c.signals[-1], "signals": c.signals})
    return out


__all__ = ["MASK", "analyze", "analyze_for_masking", "chunks", "explain"]
