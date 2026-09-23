"""Opaque HMAC token masking compatible with VibeAlfaGen token mode."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import struct

from .apply import apply_candidates
from .candidates import Candidate

logger = logging.getLogger("pii.tokens")

MARKER_RE = re.compile(r"<[A-Z0-9_]+_[a-f0-9]{32}_[0-9]+>")


def hide_markers(text: str) -> str:
    return MARKER_RE.sub(lambda match: " " * len(match.group(0)), text)


def apply_token_masks(
    text: str, candidates: list[Candidate]
) -> tuple[str, list[str], list[tuple[int, int, str]]]:
    nonce = secrets.token_hex(16)
    reserved = set(MARKER_RE.findall(text))
    values: dict[tuple[str, str], str] = {}
    counter = 0

    def token_for(candidate: Candidate) -> str:
        nonlocal counter
        key = (candidate.etype, candidate.text)
        if key in values:
            return values[key]
        while True:
            digest = hmac.new(nonce.encode("ascii"), digestmod=hashlib.sha256)
            digest.update(candidate.etype.encode("utf-8"))
            digest.update(b"\0")
            digest.update(candidate.text.encode("utf-8"))
            digest.update(struct.pack(">Q", counter))
            token = f"<{candidate.etype.upper()}_{digest.hexdigest()[:32]}_{counter}>"
            counter += 1
            if token not in reserved:
                reserved.add(token)
                values[key] = token
                return token

    return apply_candidates(text, candidates, token_for, logger=logger)
