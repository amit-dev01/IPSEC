# ADR-0006: Deterministic parsing plus a bounded metadata ML classifier

## Context
Deterministic parsing yields facts (`packet_observed`). Some questions (e.g. likely
traffic class from packet sizes/timing) are inherently inferential. An unbounded or
opaque model — or any external AI service — would violate evidence and privacy rules:
PCAPs and packet contents must never leave the deployment.

## Decision
Two-tier evidence: (1) deterministic TShark parsing is authoritative for facts;
(2) a transparent, local scikit-learn baseline classifies **metadata only** (sizes,
timing, counts, outer endpoints/SPIs — never payloads). Model output is always
labelled `model_inferred` with model version and confidence, and can never be the
sole basis for a cryptographic, application-identity, or compliance claim. Anything
the evidence cannot support is `unknown`/`insufficient_evidence`.

## Consequences
+ Honest epistemics: facts, declarations (`lab_manifest`, `analyst_supplied`),
  inferences, and unknowns stay distinguishable end-to-end (architecture §7).
+ Fully local and reproducible; no third-party AI dependency.
− The baseline's accuracy is unproven until measured on labelled lab captures; the
  product must publish measured performance or keep inferences clearly tentative.
