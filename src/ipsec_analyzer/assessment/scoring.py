"""Documented scoring formula (deterministic; no hidden weights).

Coverage: for each policy coverage dimension (weights sum to 1.0), a dimension
is 'covered' when a non-unknown fact (packet-observed, manifest, or analyst)
exists for it. coverage = sum(weights of covered dimensions).

Assessment status:
  coverage >= 0.80 -> "assessed"
  coverage >= 0.40 -> "partial"
  otherwise        -> "insufficient_evidence"

risk_score (0-100, higher = more risk):
  sum of severity weights over findings: critical 25, high 15, medium 8,
  low 3, info 0 — capped at 100. Produced only when status is partial/assessed;
  null for insufficient_evidence (a low score on thin evidence must never be
  read as "safe").

security_score (0-100, higher = stronger observed posture):
  100 - risk_score, produced ONLY when status is "assessed". Otherwise null.

Protocol-evidence confidence: mean confidence of packet_observed facts
(0 when none). ML confidence is reported separately from the classifier
result and is never merged into protocol confidence.
"""

SEVERITY_WEIGHTS = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0, "info": 0.0}


def risk_from_findings(severities: list[str]) -> float:
    return min(100.0, sum(SEVERITY_WEIGHTS.get(s, 0.0) for s in severities))
