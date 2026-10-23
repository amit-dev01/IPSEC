"""Evidence truthfulness types.

Unavailable information is represented explicitly as UNKNOWN / INSUFFICIENT_EVIDENCE.
Nothing in this package may promote unknown evidence to a secure/compliant result.
"""

from enum import StrEnum


class EvidenceStatus(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNAVAILABLE = "unavailable"
