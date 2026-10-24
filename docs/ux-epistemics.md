# UX Epistemics — Analyst UI Rules for Evidence and Uncertainty

> Purpose: the workbench must never make the evidence look stronger than
> it is. These rules bind every screen that shows facts, scores,
> classifications, or findings. They implement the backend's contracts
> (`EvidenceSource`, `EvidenceVisibility`, assessment scoring) — verified
> against backend source on 2026-10-24 — and they override visual
> convenience wherever the two conflict.

## 1. First principles

1. **Unknown is a result, not a failure — and never a pass.** An
   unobserved property is displayed as unknown with its limitation text,
   in neutral styling. It is never rendered green, never labelled
   "Secure", "Compliant", "Safe", or "Protected".
2. **Provenance is always visible.** Every fact carries its source badge
   (Section 2) wherever it appears: tables, detail panels, report views,
   exports preview. No view merges packet facts with supplied facts.
3. **Deterministic ≠ probabilistic.** Rules-engine findings and scores
   (deterministic, policy-versioned) are visually and verbally distinct
   from ML traffic inference (probabilistic) at all times (Section 6).
4. **Nothing implies decryption.** The UI never claims to inspect ESP
   payload contents, identify applications inside a tunnel, or recover
   keys. Copy says "metadata" and "inference", never "inspection" of
   encrypted content.
5. **Backend text is data, not markup.** Fact names/values, filenames,
   manifest fields, and error details render as escaped text only.

## 2. Evidence source badges (`source`)

Verified enum (`EvidenceSource`): `packet_observed`, `lab_manifest`,
`analyst_supplied`, `model_inferred`, `unknown`. The analysis detail API
already returns facts pre-grouped (`packet_observed_facts`,
`supplied_facts` = manifest + analyst, `model_inferred_facts`,
`unknown_facts`); the UI preserves those groups as separate sections and
never re-merges them into one undifferentiated table.

| Source | Badge label | Icon | Treatment |
|---|---|---|---|
| `packet_observed` | "Packet-observed" | ◎ (capture) | Strongest evidence. Solid badge. |
| `lab_manifest` | "Lab manifest" | ▣ (document) | Testbed-supplied ground truth for a *lab* run; labelled "supplied, not observed". Dashed border to signal non-observed. |
| `analyst_supplied` | "Analyst-supplied" | ✎ (person) | Human assertion; same dashed treatment, distinct label. |
| `model_inferred` | "Model-inferred" | ◈ (model) | Always paired with its confidence and the probabilistic disclaimer (Section 6). Purple/violet family, never the green/amber severity family. |
| `unknown` | "Unknown" | ? | Neutral grey, hatched/muted fill. Never green. The fact's `limitation` text is shown next to it. |

Accessibility: badges always render the text label (icon is decorative,
`aria-hidden`); the badge container exposes
`aria-label="Source: packet-observed"` (etc.). Color is redundant coding
only — the label alone must carry the meaning. Confidence, when present,
renders as `confidence 0.90` in tabular numerals next to the badge;
`null` confidence renders as "confidence —" (unknown), never as 0%.

Section headings in the analysis view are fixed and ordered:
**Packet-observed facts → Supplied facts (manifest / analyst) →
Model-inferred → Unknown / gaps.** A fact appears in exactly one section,
driven by the API grouping, not by frontend re-classification.

## 3. Visibility badges (`visibility`)

Verified enum (`EvidenceVisibility`): `visible`,
`encrypted_or_unavailable`, `derived`, `not_in_capture`, `unknown`.

| Visibility | Badge label | Rule |
|---|---|---|
| `visible` | "Visible" | Plainly observable in the capture. |
| `encrypted_or_unavailable` | "Encrypted / not observable" | **Never** shortened to "Encrypted ✓" and never green. The label states the *observability* fact; encryption here means "we cannot see it", not "it is secure". |
| `derived` | "Derived" | Computed from visible metadata (counts, sizes, timing). Tooltip/aria text: "Derived from visible metadata". |
| `not_in_capture` | "Not in capture" | The capture vantage point/window missed it (e.g. mid-session start). Distinct from encrypted. |
| `unknown` | "Visibility unknown" | Neutral, as Section 2. |

Visibility is shown as a secondary badge next to the source badge when
they differ in information value (e.g. a packet-observed fact that is
`derived`). It never replaces the source badge.

## 4. Scores and assessment status

Backend semantics (verified in `assessment/scoring.py` and the report
builder):

- **Coverage** = weighted fraction of policy dimensions backed by
  non-unknown evidence. Status: coverage ≥ 0.80 → `assessed`;
  0.40–0.79 → `partial`; < 0.40 → `insufficient_evidence`.
- **risk_score** (0–100, higher = more risk) is produced only for
  `partial`/`assessed`; it is **`null` for `insufficient_evidence`**.
- **security_score** (0–100, higher = stronger *observed* posture) =
  100 − risk, produced **only when `assessed`**; otherwise `null`.

Presentation rules (implemented by `lib/scores.ts`, unit-tested):

| Situation | Display |
|---|---|
| `insufficient_evidence` | Amber/grey banner: "Insufficient evidence — assessment withheld." Both scores shown as "Not scored" (em dash + label). **Never** a 0, never green, never "low risk". Coverage bar shown with the missing dimensions named. |
| `partial` | Amber banner: "Partial assessment — some settings unknown (listed as gaps)." risk_score may display with the label "Risk (partial evidence)"; security_score shown as "Withheld until fully assessed", never computed in the browser as 100 − risk. |
| `assessed` | Both scores display with definitions one click away ("How is this scored?" → policy version, severity weights, coverage). Score color follows the *value* with an accompanying text label (e.g. "Risk 72 / 100 — high"). The word "Secure" is not used; the security score is labelled "Observed posture". |
| Any `null` model/policy field | `model_version: null` → "No model result"; never a placeholder model name or invented score. |

Severity badges for findings (`info | low | medium | high | critical`)
pair the word with a shape icon (● ▲ ■ ◆ ⬟ or equivalent non-color cue)
and `aria-label="Severity: high"`. `info` findings (including all
evidence-gap `GAP-*` findings) are informational, styled neutrally, and
never counted in UI copy as "vulnerabilities". Evidence gaps get their
own list ("Evidence gaps") separate from findings, mirroring the API's
`findings` / `evidence_gaps` split. Each finding shows rule ID
(monospace), actual vs expected values, recommendation, evidence
reference count, and `policy_version` — all as text.

## 5. Protocol structure separations

The UI keeps these distinctions structurally — separate tables/panels,
never a single blended "crypto settings" list:

- **IKE SA vs Child SA.** Fact names are namespaced (`ike_sa.*`,
  `child_sa.*`, `esp.*`) and rendered under separate headings ("IKE SA",
  "Child SA / ESP"). Child-SA parameters negotiated inside encrypted
  IKE messages are commonly `unknown` — displayed as gaps with
  limitation text, not interpolated from IKE SA values. Nothing copies
  an IKE SA transform into the Child SA panel.
- **Offered vs Selected transforms.** `ike_sa.offered.*` (peer's proposal
  list in IKE_SA_INIT) and `ike_sa.selected.*` (the single negotiated
  choice) are separate columns/tables with the headings "Offered
  (proposed)" and "Selected (negotiated)". A weak algorithm that was
  merely *offered* is visually weaker evidence than one *selected*
  (the backend already severities them differently); the UI copy says
  "offered but not selected" where applicable and never describes an
  offered-only algorithm as "in use".
- **ESP reality check.** `esp.encryption_algorithm` from passive
  observation is normally `null` (unknown). The UI shows "ESP cipher:
  Unknown — not observable from ESP traffic" rather than guessing from
  IKE or manifest data; manifest ESP claims appear only in the Supplied
  section and are labelled as such.

## 6. ML traffic inference vs protocol confidence

Two different confidences exist and are never averaged, merged, or
shown on the same gauge:

| | Protocol-evidence confidence | ML traffic confidence |
|---|---|---|
| Meaning | Mean confidence of packet-observed facts (backend definition) | Classifier confidence for a *probabilistic* metadata category |
| Determinism | Deterministic evidence quality | Probabilistic model output |
| Display | Neutral/blue gauge labelled "Protocol-evidence confidence" with definition tooltip | Violet gauge labelled "Model confidence (probabilistic)" always beside the category and disclaimer |

Copy rules for ML output (`predicted_category`, `model_version`,
statuses such as unavailable/abstain → shown as "Unknown category"):

- Heading: **"Likely traffic category (metadata inference)"** — never
  "Application detected", "Traffic identified", or a vendor/app name
  presented as fact. A `lab_application_label` from a manifest is lab
  ground truth for evaluation only and is labelled "Lab label (testbed
  only — not a production prediction)".
- Permanent disclaimer next to every ML result: "Inferred from packet
  sizes, timing, and flow metadata only. ESP payloads are encrypted and
  are not inspected; this is not application identification."
- When the classifier is unavailable or abstains, the panel shows
  "Model result: unavailable/unknown" with the backend status — never a
  default category, never a fabricated confidence number. Absence of an
  ML result does not change the deterministic assessment's styling.

## 7. Copy do / don't (binding examples)

| ✅ Do | ❌ Don't |
|---|---|
| "ESP cipher: Unknown — not observable passively" | "ESP encryption: Secure" |
| "Partial assessment (coverage 55%) — gaps listed below" | "Mostly secure" |
| "Offered: 3DES, AES-CBC · Selected: AES-GCM" | "Uses 3DES" (when only offered) |
| "Likely category: video-like traffic (model, 0.71)" | "Detected: YouTube traffic" |
| "Not scored — insufficient evidence" | "Risk: 0" on thin evidence |
| "Encrypted / not observable" | "Encrypted ✓ Protected" |
| Show the backend `limitation` sentence verbatim | Invent a reason for a gap |
