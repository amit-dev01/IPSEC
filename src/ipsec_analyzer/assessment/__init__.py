"""Deterministic, versioned assessment rules over evidence.

Unknown is never a pass. Scores are documented in `assessment/scoring.py` and
in the README: risk_score is 0-100 (higher = more risk) whenever evidence
coverage is at least partial; security_score (0-100, higher = stronger
posture) is only produced when coverage is sufficient for `assessed` status.
No profile here certifies regulatory compliance.
"""
