import type { ReactNode } from "react";
import { useState } from "react";
import { jsPDF } from "jspdf";

import type { AnalysisDetail } from "@/api/client";
import { useToast } from "@/app/toast-context";
import { buildComplianceJson } from "./reportTemplate";

interface ReportExportButtonProps {
  detail: AnalysisDetail;
}

export default function ReportExportButton({ detail }: ReportExportButtonProps): ReactNode {
  const [generatingPdf, setGeneratingPdf] = useState(false);
  const toast = useToast();

  const handleExportJson = (): void => {
    try {
      const data = buildComplianceJson(detail);
      const jsonStr = JSON.stringify(data, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `ipsec_compliance_${detail.id.slice(0, 8)}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      toast.push("success", "Compliance JSON report exported.");
    } catch {
      toast.push("error", "Failed to export JSON report.");
    }
  };

  const handleExportPdf = async (): Promise<void> => {
    setGeneratingPdf(true);
    try {
      const report = buildComplianceJson(detail);
      const doc = new jsPDF({
        orientation: "portrait",
        unit: "mm",
        format: "a4",
      });

      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      let y = 14;

      // Header Banner
      doc.setFillColor(18, 18, 24);
      doc.rect(0, 0, pageWidth, 28, "F");

      // Signal Violet accent stripe
      doc.setFillColor(175, 80, 255);
      doc.rect(0, 28, pageWidth, 2, "F");

      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.text("IPSEC COMPLIANCE & POSTURE AUDIT", 14, 13);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(180, 180, 200);
      doc.text("Zero-Trust Cryptographic Evidence Audit | RFC & NIST SP 800-77 Benchmark", 14, 21);

      y = 40;

      // Metadata section
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 70);
      doc.setFont("helvetica", "bold");
      doc.text("AUDIT METADATA", 14, y);
      y += 5;

      doc.setDrawColor(220, 220, 230);
      doc.setLineWidth(0.3);
      doc.line(14, y, pageWidth - 14, y);
      y += 6;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(80, 80, 90);

      doc.text(`Analysis ID: ${detail.id}`, 14, y);
      doc.text(`Capture ID: ${detail.capture_id}`, 110, y);
      y += 5;
      doc.text(`Generated: ${new Date(report.generated_at).toLocaleString()}`, 14, y);
      doc.text(`Policy Version: ${detail.policy_version}`, 110, y);
      y += 8;

      // Executive Score Card Box
      doc.setFillColor(248, 249, 252);
      doc.roundedRect(14, y, pageWidth - 28, 26, 2, 2, "F");
      doc.setDrawColor(210, 215, 230);
      doc.roundedRect(14, y, pageWidth - 28, 26, 2, 2, "S");

      // Score 1: Security Score
      const secScore = detail.security_score ?? 0;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(18);
      if (secScore >= 80) doc.setTextColor(24, 150, 70);
      else if (secScore >= 50) doc.setTextColor(220, 140, 20);
      else doc.setTextColor(210, 40, 40);
      doc.text(detail.security_score !== null ? `${secScore}/100` : "WITHHELD", 20, y + 14);

      doc.setFontSize(8);
      doc.setTextColor(110, 110, 130);
      doc.setFont("helvetica", "normal");
      doc.text("SECURITY SCORE", 20, y + 20);

      // Score 2: Risk Score
      const riskScore = detail.risk_score ?? 0;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(18);
      doc.setTextColor(70, 70, 90);
      doc.text(detail.risk_score !== null ? `${riskScore}/100` : "WITHHELD", 75, y + 14);

      doc.setFontSize(8);
      doc.setTextColor(110, 110, 130);
      doc.setFont("helvetica", "normal");
      doc.text("RISK INDEX", 75, y + 20);

      // Score 3: Compliance Index
      doc.setFont("helvetica", "bold");
      doc.setFontSize(18);
      doc.setTextColor(140, 60, 220);
      doc.text(`${report.executive_summary.compliance_percentage}%`, 130, y + 14);

      doc.setFontSize(8);
      doc.setTextColor(110, 110, 130);
      doc.setFont("helvetica", "normal");
      doc.text("RFC COMPLIANCE INDEX", 130, y + 20);

      // Verdict badge
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(40, 40, 60);
      doc.text(`VERDICT: ${report.executive_summary.verdict}`, 14, y + 33);
      y += 40;

      // RFC Compliance Matrix Table Header
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 70);
      doc.text("RFC CRYPTOGRAPHIC COMPLIANCE MATRIX", 14, y);
      y += 5;

      // Table Header Row
      doc.setFillColor(235, 238, 246);
      doc.rect(14, y, pageWidth - 28, 6, "F");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(7.5);
      doc.setTextColor(50, 50, 70);

      doc.text("STANDARD / ALGORITHM", 16, y + 4.2);
      doc.text("DOMAIN", 72, y + 4.2);
      doc.text("RFC CITATION", 100, y + 4.2);
      doc.text("REQ", 132, y + 4.2);
      doc.text("OBSERVED", 146, y + 4.2);
      doc.text("VERDICT", 176, y + 4.2);
      y += 7;

      // Table Data Rows
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);

      for (const row of report.rfc_compliance_matrix) {
        if (y > pageHeight - 25) {
          doc.addPage();
          y = 15;
        }

        doc.setTextColor(40, 40, 50);
        doc.text(row.algorithm.slice(0, 32), 16, y + 3.5);
        doc.setTextColor(90, 90, 100);
        doc.text(row.domain, 72, y + 3.5);
        doc.text(row.rfc_citation, 100, y + 3.5);
        doc.text(row.requirement, 132, y + 3.5);
        doc.text(row.observed_value.slice(0, 18), 146, y + 3.5);

        if (row.verdict === "COMPLIANT") {
          doc.setTextColor(24, 140, 60);
        } else if (row.verdict === "NON-COMPLIANT") {
          doc.setTextColor(200, 30, 30);
        } else {
          doc.setTextColor(120, 120, 130);
        }
        doc.text(row.verdict, 176, y + 3.5);

        y += 5.2;
        doc.setDrawColor(235, 235, 240);
        doc.line(14, y, pageWidth - 14, y);
      }

      y += 6;

      // Key Findings Section
      if (y > pageHeight - 45) {
        doc.addPage();
        y = 15;
      }

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 70);
      doc.text(`IDENTIFIED SECURITY FINDINGS (${detail.findings.length})`, 14, y);
      y += 5;

      if (detail.findings.length === 0) {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(30, 140, 60);
        doc.text("No security violations or deprecated transforms detected in this capture.", 14, y + 4);
        y += 10;
      } else {
        for (const finding of detail.findings.slice(0, 6)) {
          if (y > pageHeight - 20) {
            doc.addPage();
            y = 15;
          }

          const sev = finding.severity.toUpperCase();
          if (sev === "CRITICAL") doc.setTextColor(200, 30, 30);
          else if (sev === "HIGH") doc.setTextColor(220, 100, 20);
          else if (sev === "MEDIUM") doc.setTextColor(180, 140, 20);
          else doc.setTextColor(80, 80, 100);

          doc.setFont("helvetica", "bold");
          doc.setFontSize(7.5);
          doc.text(`[${sev}] ${finding.rule_id}`, 16, y + 3.5);

          doc.setFont("helvetica", "normal");
          doc.setTextColor(70, 70, 80);
          const recText = finding.recommendation ? `Recommendation: ${finding.recommendation}` : "";
          const splitRec = doc.splitTextToSize(recText, pageWidth - 32);
          doc.text(splitRec, 16, y + 7.5);

          y += 9 + splitRec.length * 3.5;
        }
      }

      // Footer
      const totalPages = doc.getNumberOfPages();
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setFontSize(6.5);
        doc.setTextColor(140, 140, 150);
        doc.text(
          "CONFIDENTIAL & PROPRIETARY — IPSEC COMPLIANCE ANALYZER — NOT A REGULATORY ACCREDITATION",
          14,
          pageHeight - 8,
        );
        doc.text(`Page ${i} of ${totalPages}`, pageWidth - 25, pageHeight - 8);
      }

      doc.save(`ipsec_compliance_report_${detail.id.slice(0, 8)}.pdf`);
      toast.push("success", "Compliance PDF report generated.");
    } catch {
      toast.push("error", "Failed to generate PDF report.");
    } finally {
      setGeneratingPdf(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={() => void handleExportPdf()}
        disabled={generatingPdf}
        className="inline-flex items-center gap-1.5 rounded border border-signal-violet bg-signal-violet/10 px-3 py-1.5 text-xs font-medium text-signal-violet transition hover:bg-signal-violet hover:text-white disabled:opacity-50"
      >
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        {generatingPdf ? "Compiling PDF..." : "Export Compliance PDF"}
      </button>

      <button
        type="button"
        onClick={handleExportJson}
        className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-raised px-3 py-1.5 text-xs font-medium text-ink transition hover:border-signal-violet hover:text-signal-violet"
      >
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
        Export Compliance JSON
      </button>
    </div>
  );
}
