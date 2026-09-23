"""Public domain API for PII request processing."""

from .errors import (
    DemaskDenied,
    MaskingFailed,
    MaskingTimeout,
    PayloadConflict,
    ProcessingError,
    StoreUnavailable,
    SystemNotAllowed,
)
from .policy import ProcessingPolicy, build_policy
from .processor import Processor, ProcessResult, process_existing, storage_key

__all__ = [
    "DemaskDenied",
    "MaskingFailed",
    "MaskingTimeout",
    "PayloadConflict",
    "ProcessResult",
    "ProcessingError",
    "ProcessingPolicy",
    "Processor",
    "StoreUnavailable",
    "SystemNotAllowed",
    "build_policy",
    "process_existing",
    "storage_key",
]
