import type { ReactNode } from "react";
import { useMemo, useState } from "react";

import type { AnalysisDetail } from "@/api/client";
import { RFC_CATALOG, type ComplianceVerdict, type RfcDomain } from "./rfcCatalog";

interface ComplianceMatrixProps {
  detail: AnalysisDetail;
}

export default function ComplianceMatrix({ detail }: ComplianceMatrixProps): ReactNode {
  const [search, setSearch] = useState<string>("");
  const [selectedDomain, setSelectedDomain] = useState<string>("all");
  const [selectedVerdict, setSelectedVerdict] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Evaluate all standards against the active analysis detail
  const evaluations = useMemo(() => {
    return RFC_CATALOG.map((std) => {
      const result = std.evaluator(detail);
      return {
        ...std,
        result,
      };
    });
  }, [detail]);

  // Aggregate stats
  const stats = useMemo(() => {
    let compliant = 0;
    let warning = 0;
    let nonCompliant = 0;
    let notObserved = 0;

    for (const e of evaluations) {
      if (e.result.verdict === "compliant") compliant++;
      else if (e.result.verdict === "warning") warning++;
      else if (e.result.verdict === "non-compliant") nonCompliant++;
      else notObserved++;
    }

    return {
      total: evaluations.length,
      compliant,
      warning,
      nonCompliant,
      notObserved,
      score: Math.round((compliant / Math.max(1, compliant + warning + nonCompliant)) * 100),
    };
  }, [evaluations]);

  // Filtered rows
  const filtered = useMemo(() => {
    return evaluations.filter((item) => {
      if (selectedDomain !== "all" && item.domain !== selectedDomain) return false;
      if (selectedVerdict !== "all" && item.result.verdict !== selectedVerdict) return false;
      if (search.trim() !== "") {
        const q = search.toLowerCase();
        const matches =
          item.title.toLowerCase().includes(q) ||
          item.algorithm.toLowerCase().includes(q) ||
          item.rfc.toLowerCase().includes(q) ||
          item.nistRef.toLowerCase().includes(q) ||
          (item.result.observedValue && item.result.observedValue.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [evaluations, selectedDomain, selectedVerdict, search]);

  const exportCsv = (): void => {
    const headers = [
      "Standard",
      "Algorithm",
      "Domain",
      "RFC Citation",
      "NIST Reference",
      "Requirement",
      "Observed Value",
      "Verdict",
      "Notes",
    ];

    const rows = evaluations.map((e) => [
      `"${e.title.replace(/"/g, '""')}"`,
      `"${e.algorithm.replace(/"/g, '""')}"`,
      `"${e.domain}"`,
      `"${e.rfc}"`,
      `"${e.nistRef}"`,
      `"${e.requirement}"`,
      `"${(e.result.observedValue ?? "Not Observed").replace(/"/g, '""')}"`,
      `"${e.result.verdict.toUpperCase()}"`,
      `"${e.result.notes.replace(/"/g, '""')}"`,
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `compliance_matrix_${detail.id.slice(0, 8)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const domains: RfcDomain[] = [
    "Architecture",
    "Key Exchange",
    "Encryption",
    "Integrity",
    "Anti-Replay",
  ];

  return (
    <div className="space-y-6 py-4">
      {/* Header and Summary Cards */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-ink-bright">
            Cryptographic Compliance Matrix
          </h2>
          <p className="text-xs text-ink-muted">
            Cross-referenced evaluation against RFC specifications, NIST SP 800-77 Rev. 1, and CNSA 2.0.
          </p>
        </div>
        <button
          type="button"
          onClick={exportCsv}
          className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-raised px-3 py-1.5 text-xs font-medium text-ink transition hover:border-signal-violet hover:text-signal-violet"
        >
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          Export Matrix (.CSV)
        </button>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div className="rounded border border-line bg-surface-sunken p-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">Standards</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-ink-bright">{stats.total}</p>
          <p className="text-[10px] text-ink-muted">Audited controls</p>
        </div>
        <div className="rounded border border-line bg-surface-sunken p-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-sev-low">Compliant</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-sev-low">{stats.compliant}</p>
          <p className="text-[10px] text-ink-muted">Passes RFC / NIST criteria</p>
        </div>
        <div className="rounded border border-line bg-surface-sunken p-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-sev-medium">Warnings</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-sev-medium">{stats.warning}</p>
          <p className="text-[10px] text-ink-muted">Suboptimal / legacy</p>
        </div>
        <div className="rounded border border-line bg-surface-sunken p-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-sev-critical">Non-Compliant</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-sev-critical">{stats.nonCompliant}</p>
          <p className="text-[10px] text-ink-muted">Prohibited algorithms</p>
        </div>
        <div className="col-span-2 rounded border border-line bg-surface-sunken p-3 sm:col-span-1">
          <p className="text-[11px] font-medium uppercase tracking-wider text-signal-violet">Compliance Index</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-signal-violet">{stats.score}%</p>
          <p className="text-[10px] text-ink-muted">Observed pass ratio</p>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col gap-3 rounded border border-line bg-surface-raised p-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-ink-muted">Domain:</span>
          <button
            type="button"
            onClick={() => setSelectedDomain("all")}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              selectedDomain === "all"
                ? "bg-signal-violet text-white"
                : "bg-surface-sunken text-ink-muted hover:text-ink"
            }`}
          >
            All
          </button>
          {domains.map((dom) => (
            <button
              key={dom}
              type="button"
              onClick={() => setSelectedDomain(dom)}
              className={`rounded px-2.5 py-1 text-xs font-medium transition ${
                selectedDomain === dom
                  ? "bg-signal-violet text-white"
                  : "bg-surface-sunken text-ink-muted hover:text-ink"
              }`}
            >
              {dom}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-ink-muted">
            Verdict:
            <select
              value={selectedVerdict}
              onChange={(e) => setSelectedVerdict(e.target.value)}
              className="rounded border border-line bg-surface-sunken px-2 py-1 text-xs text-ink outline-none focus:border-signal-violet"
            >
              <option value="all">All Verdicts</option>
              <option value="compliant">Compliant</option>
              <option value="warning">Warning / Legacy</option>
              <option value="non-compliant">Non-Compliant</option>
              <option value="not-observed">Not Observed</option>
            </select>
          </label>

          <input
            type="search"
            placeholder="Search standards, RFC, algorithm..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded border border-line bg-surface-sunken px-2.5 py-1 text-xs text-ink placeholder:text-ink-muted focus:border-signal-violet focus:outline-none"
          />
        </div>
      </div>

      {/* Compliance Table */}
      <div className="overflow-x-auto rounded border border-line bg-surface-raised">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-line bg-surface-sunken text-[11px] uppercase tracking-wider text-ink-muted">
            <tr>
              <th className="px-4 py-3 font-semibold">Standard & Algorithm</th>
              <th className="px-3 py-3 font-semibold">Domain</th>
              <th className="px-3 py-3 font-semibold">RFC Citation</th>
              <th className="px-3 py-3 font-semibold">Standard Level</th>
              <th className="px-3 py-3 font-semibold">Observed in Capture</th>
              <th className="px-4 py-3 font-semibold">Verdict</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-ink-muted">
                  No standards match the selected filters.
                </td>
              </tr>
            ) : (
              filtered.map((item) => {
                const isExpanded = expandedId === item.id;
                const v = item.result.verdict;

                let verdictBg = "bg-surface-sunken text-ink-muted border-line";
                let verdictIcon = "—";
                let verdictLabel = "NOT OBSERVED";

                if (v === "compliant") {
                  verdictBg = "bg-sev-low/10 text-sev-low border-sev-low/30";
                  verdictIcon = "✓";
                  verdictLabel = "COMPLIANT";
                } else if (v === "warning") {
                  verdictBg = "bg-sev-medium/10 text-sev-medium border-sev-medium/30";
                  verdictIcon = "▲";
                  verdictLabel = "LEGACY / WARN";
                } else if (v === "non-compliant") {
                  verdictBg = "bg-sev-critical/10 text-sev-critical border-sev-critical/30";
                  verdictIcon = "✗";
                  verdictLabel = "VIOLATION";
                }

                let reqClass = "text-ink-muted";
                if (item.requirement === "MUST") reqClass = "text-signal-violet font-semibold";
                else if (item.requirement === "MUST NOT") reqClass = "text-sev-critical font-semibold";

                return (
                  <tr
                    key={item.id}
                    onClick={() => setExpandedId(isExpanded ? null : item.id)}
                    className="cursor-pointer transition-colors hover:bg-surface-sunken/60"
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-ink-bright">{item.title}</div>
                      <div className="mono text-[11px] text-ink-muted">{item.algorithm}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span className="inline-block rounded border border-line bg-surface-sunken px-2 py-0.5 text-[10px] font-medium text-ink-muted">
                        {item.domain}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <a
                        href={item.rfcUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="mono inline-flex items-center gap-1 font-medium text-signal-violet underline hover:text-signal-violet/80"
                      >
                        {item.rfc}
                        <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </a>
                      <div className="text-[10px] text-ink-muted">{item.nistRef}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span className={`text-xs ${reqClass}`}>{item.requirement}</span>
                    </td>
                    <td className="px-3 py-3">
                      {item.result.observed ? (
                        <div className="mono font-semibold text-ink-bright">
                          {item.result.observedValue ?? "Detected"}
                        </div>
                      ) : (
                        <span className="text-ink-muted italic">Not observable</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] font-semibold tracking-wider ${verdictBg}`}
                      >
                        <span>{verdictIcon}</span>
                        <span>{verdictLabel}</span>
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Expanded Details Drawer */}
      {expandedId && (
        <div className="rounded border border-signal-violet/40 bg-surface-raised p-4 transition-all">
          {(() => {
            const item = evaluations.find((e) => e.id === expandedId);
            if (!item) return null;
            return (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-ink-bright">
                    {item.title} ({item.algorithm})
                  </h4>
                  <button
                    type="button"
                    onClick={() => setExpandedId(null)}
                    className="text-xs text-ink-muted hover:text-ink"
                  >
                    ✕ Close details
                  </button>
                </div>
                <p className="text-xs text-ink">{item.description}</p>
                <div className="mt-2 rounded bg-surface-sunken p-2.5 text-xs">
                  <span className="font-semibold text-signal-violet">Audit Evaluation Note: </span>
                  <span className="text-ink">{item.result.notes}</span>
                </div>
                <div className="flex flex-wrap gap-4 text-[11px] text-ink-muted pt-1">
                  <span>Requirement: <strong>{item.requirement}</strong></span>
                  <span>Specification: <strong>{item.rfc}</strong></span>
                  <span>Authority Guideline: <strong>{item.nistRef}</strong></span>
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
