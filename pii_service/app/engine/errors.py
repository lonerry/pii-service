"""Typed failures raised by the framework-independent processing engine."""
from __future__ import annotations


class ProcessingError(Exception):
    """Base class for domain failures."""


class SystemNotAllowed(ProcessingError):
    """The requested system is missing or disabled."""


class PayloadConflict(ProcessingError):
    """The payload id is already bound to different content."""


class DemaskDenied(ProcessingError):
    """A saved masked value was supplied but demasking is disabled."""


class MaskingTimeout(ProcessingError):
    """Masking exceeded the configured deadline."""


class MaskingFailed(ProcessingError):
    """The masking implementation failed."""


class StoreUnavailable(ProcessingError):
    """The record store could not complete an operation."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"store {operation} failed")


class RecordDecryptFailed(ProcessingError):
    """A stored record exists but cannot be decrypted with the current key."""
