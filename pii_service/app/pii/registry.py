"""Typed detector registry modeled after VibeAlfaGen's Registry."""
from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from .candidates import Candidate

Detector = Callable[[str], list[Candidate]]


@dataclass(frozen=True)
class Registration:
    types: frozenset[str]
    detector: Detector


class Registry:
    def __init__(self, registrations: Sequence[Registration]) -> None:
        self._registrations = tuple(registrations)
        self._supported = frozenset(
            entity_type
            for registration in registrations
            for entity_type in registration.types
        )

    @property
    def registrations(self) -> tuple[Registration, ...]:
        return self._registrations

    @property
    def supported_types(self) -> frozenset[str]:
        return self._supported

    def collect(self, text: str, types: Iterable[str]) -> list[Candidate]:
        wanted = frozenset(types)
        unavailable = wanted - self._supported
        if unavailable:
            raise ValueError(f"required detector unavailable: {sorted(unavailable)}")
        findings: list[Candidate] = []
        for registration in self._registrations:
            if registration.types.isdisjoint(wanted):
                continue
            for candidate in registration.detector(text):
                if candidate.etype not in wanted:
                    continue
                self._validate(text, candidate)
                findings.append(candidate)
        return findings

    @staticmethod
    def _validate(text: str, candidate: Candidate) -> None:
        if candidate.start < 0 or candidate.end <= candidate.start or candidate.end > len(text):
            raise ValueError("invalid detector span")
        if math.isnan(candidate.score) or not 0 <= candidate.score <= 1:
            raise ValueError("invalid detector confidence")
        if text[candidate.start:candidate.end] != candidate.text:
            raise ValueError("detector span does not match input")
