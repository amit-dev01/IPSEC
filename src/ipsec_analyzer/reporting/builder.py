"""Build the structured report document for a completed AnalysisRun."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ipsec_analyzer.models import AnalysisRun, Capture, EvidenceRecord, Finding

SCORE_DEFINITIONS = {
    "risk_score": "0-100, higher = more risk. Sum of finding severity weights "
    "(critical 25, high 15, medium 8, low 3, info 0), capped at 100. Null when "
    "evidence coverage is insufficient — a null/low score is never a safety claim.",
    "security_score": "0-100, higher = stronger observed posture (100 - risk_score). "
    "Produced only when assessment status is 'assessed'; otherwise null.",
    "coverage": "Weighted fraction of assessment dimensions backed by non-unknown "
    "evidence (see policy profile weights).",
    "protocol_evidence_confidence": "Mean confidence of packet-observed facts (0-1).",
    "ml_traffic_confidence": "Calibrated classifier confidence (0-1), reported "
    "separately; probabilistic metadata inference, not application identification.",
}


def build_report(db: Session, run: AnalysisRun) -> dict[str, Any]:
    capture = db.get(Capture, run.capture_id)
    evidence = list(
        db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.analysis_id == run.id)
            .order_by(EvidenceRecord.fact_name)
        )
    )
    findings = list(
        db.scalars(select(Finding).where(Finding.analysis_id == run.id).order_by(Finding.rule_id))
    )
    summary = run.summary or {}
    assessment = summary.get("assessment") or {}

    def fact(e: EvidenceRecord) -> dict[str, Any]:
        return {
            "fact": e.fact_name,
            "value": e.fact_value,
            "source": str(e.source),
            "visibility": str(e.visibility),
            "confidence": e.confidence,
            "quality": e.quality,
            "packet_refs": e.packet_refs,
            "limitation": e.limitation,
        }

    packet_facts = [fact(e) for e in evidence if str(e.source) == "packet_observed"]
    supplied_facts = [
        fact(e) for e in evidence if str(e.source) in ("lab_manifest", "analyst_supplied")
    ]
    model_facts = [fact(e) for e in evidence if str(e.source) == "model_inferred"]
    unknowns = [fact(e) for e in evidence if str(e.source) == "unknown" or e.fact_value is None]
    ml_prediction = summary.get("ml_prediction") or {}
    status = assessment.get("status", "insufficient_evidence")

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "analysis_id": str(run.id),
        "capture": {
            "id": str(run.capture_id),
            "display_name": capture.display_name if capture else None,
            "sha256": capture.sha256 if capture else None,
            "format": str(capture.format) if capture else None,
            "size_bytes": capture.size_bytes if capture else None,
        },
        "executive_summary": {
            "assessment_status": status,
            "headline": _headline(status, run, len(findings)),
            "risk_score": run.risk_score,
            "security_score": run.security_score,
            "coverage": assessment.get("coverage"),
            "finding_counts": _severity_counts(findings),
            "note": "Scores summarize observed evidence only. Unknown settings are "
            "reported as gaps, never as passing. This report is not a certification "
            "or regulatory-compliance claim.",
        },
        "scores_and_definitions": {
            "risk_score": run.risk_score,
            "security_score": run.security_score,
            "coverage": assessment.get("coverage"),
            "protocol_evidence_confidence": assessment.get("protocol_evidence_confidence"),
            "ml_traffic_confidence": assessment.get("ml_traffic_confidence"),
            "definitions": SCORE_DEFINITIONS,
        },
        "packet_observed_facts": packet_facts,
        "manifest_and_analyst_facts": supplied_facts,
        "model_inferred": {
            "prediction": ml_prediction,
            "facts": model_facts,
            "disclaimer": "Traffic categories are probabilistic metadata inference, "
            "not application identification.",
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": str(f.severity),
                "confidence": f.confidence,
                "actual_value": f.actual_value,
                "expected_value": f.expected_value,
                "recommendation": f.recommendation,
                "evidence_refs": f.evidence_refs,
                "policy_version": f.policy_version,
                "source_refs": f.source_refs,
                "status": str(f.status),
            }
            for f in findings
        ],
        "metadata_exposure": {
            "outer_endpoints": next(
                (f["value"] for f in packet_facts if f["fact"] == "network.outer_endpoints"),
                None,
            ),
            "nat_traversal_observed": next(
                (f["value"] for f in packet_facts if f["fact"] == "ike.nat_traversal_observed"),
                None,
            ),
            "note": "Outer endpoint/timing metadata is inherently visible to passive "
            "observers; endpoint identifiers are hashed unless explicitly configured.",
        },
        "unknowns_and_limitations": {
            "unknowns": unknowns,
            "parse_limitations": summary.get("parse_limitations"),
            "truncation_warnings": summary.get("truncation_warnings"),
            "truncated": summary.get("truncated"),
        },
        "versions": {
            "pipeline_version": run.pipeline_version,
            "parser_version": summary.get("parser_version"),
            "tshark_version": summary.get("tshark_version"),
            "model_version": run.model_version,
            "policy_version": run.policy_version,
        },
        "timestamps": {
            "queued_at": run.queued_at.isoformat() if run.queued_at else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        },
    }


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    return counts


def _headline(status: str, run: AnalysisRun, finding_count: int) -> str:
    if status == "insufficient_evidence":
        return (
            "Insufficient evidence: the capture does not expose enough configuration "
            "to assess this VPN. Scores are intentionally withheld."
        )
    if status == "partial":
        return (
            f"Partial assessment ({finding_count} findings): some settings remain "
            "unknown and are listed as gaps, not passes."
        )
    return f"Assessed ({finding_count} findings) against policy {run.policy_version}."
