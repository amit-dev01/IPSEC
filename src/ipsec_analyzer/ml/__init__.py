"""Transparent, local metadata-only ML baseline.

Features come only from flow metadata (counts, length/timing statistics,
direction, bursts, duration, byte rate, ESP/NAT-T session metadata). Payloads,
decrypted content, usernames, raw IP addresses, domains, and external lookups
are never features. Predictions are probabilistic metadata inference — not
application identification — and the classifier abstains (`unknown`) below a
calibrated-confidence threshold. With no trusted model installed, inference
returns `unavailable`, never a fabricated prediction.
"""
