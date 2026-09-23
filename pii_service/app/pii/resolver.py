"""Span Resolver: централизованное разрешение пересечений кандидатов."""
from __future__ import annotations

from .candidates import MASK, Candidate


def dedupe(cands: list[Candidate]) -> list[Candidate]:
    """Одинаковый span+тип от разных детекторов → один кандидат с max score."""
    best: dict[tuple[int, int, str], Candidate] = {}
    for c in cands:
        k = (c.start, c.end, c.etype)
        cur = best.get(k)
        if cur is None:
            best[k] = c
            continue
        cur.signals.extend(s for s in c.signals if s not in cur.signals)
        merged_evidence = {**c.evidence, **cur.evidence}
        if (c.labeled, c.effective_score) > (cur.labeled, cur.effective_score):
            c.signals = cur.signals
            c.evidence = merged_evidence
            best[k] = c
        else:
            cur.evidence = merged_evidence
    return list(best.values())


def _better(left: Candidate, right: Candidate) -> bool:
    if left.effective_score != right.effective_score:
        return left.effective_score > right.effective_score
    if left.length != right.length:
        return left.length > right.length
    return left.start < right.start


def select(text: str, cands: list[Candidate]) -> list[Candidate]:
    masked = [candidate for candidate in cands if candidate.action == MASK]
    masked.sort(
        key=lambda candidate: (
            candidate.start,
            -candidate.effective_score,
            -candidate.length,
        )
    )
    accepted: list[Candidate] = []
    for candidate in masked:
        if not accepted or candidate.start >= accepted[-1].end:
            accepted.append(candidate)
            continue
        previous = accepted[-1]
        union_start = previous.start
        union_end = max(previous.end, candidate.end)
        winner = candidate if _better(candidate, previous) else previous
        merged_types = {
            previous.etype,
            candidate.etype,
            *(signal.removeprefix("merged_type:") for signal in previous.signals if signal.startswith("merged_type:")),
            *(signal.removeprefix("merged_type:") for signal in candidate.signals if signal.startswith("merged_type:")),
        }
        winner.signals.extend(
            f"merged_type:{etype}"
            for etype in sorted(merged_types)
            if etype != winner.etype and f"merged_type:{etype}" not in winner.signals
        )
        winner.start = union_start
        winner.end = union_end
        winner.text = text[union_start:union_end]
        accepted[-1] = winner
    return accepted
