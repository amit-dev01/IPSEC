import type { ReactNode } from "react";
import { useMemo, useState } from "react";

import type { AnalysisDetail } from "@/api/client";
import { RFC_CATALOG, type RfcDomain } from "./rfcCatalog";

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

    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
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
    <div className="space-y-6">
      {/* Header and Summary Cards */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="font-display text-xl font-semibold tracking-tight text-[#1d1d1f]">
            Cryptographic Compliance Matrix
          </h2>
          <p className="mt-1 text-xs text-[#707070]">
            Cross-referenced evaluation against RFC specifications, NIST SP 800-77 Rev. 1, and CNSA
            2.0.
          </p>
        </div>
        <button type="button" onClick={exportCsv} className="apple-btn-secondary text-xs">
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          Export Matrix (.CSV)
        </button>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div className="apple-card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#707070]">
            Standards
          </p>
          <p className="font-display mt-2 text-3xl font-semibold tracking-tight text-[#1d1d1f]">
            {stats.total}
          </p>
          <p className="mt-1 text-[11px] text-[#707070]">Audited controls</p>
        </div>
        <div className="apple-card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#0071e3]">
            Compliant
          </p>
          <p className="font-display mt-2 text-3xl font-semibold tracking-tight text-[#0071e3]">
            {stats.compliant}
          </p>
          <p className="mt-1 text-[11px] text-[#707070]">Passes RFC / NIST criteria</p>
        </div>
        <div className="apple-card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#ff9500]">
            Warnings
          </p>
          <p className="font-display mt-2 text-3xl font-semibold tracking-tight text-[#ff9500]">
            {stats.warning}
          </p>
          <p className="mt-1 text-[11px] text-[#707070]">Suboptimal / legacy</p>
        </div>
        <div className="apple-card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#d70015]">
            Non-Compliant
          </p>
          <p className="font-display mt-2 text-3xl font-semibold tracking-tight text-[#d70015]">
            {stats.nonCompliant}
          </p>
          <p className="mt-1 text-[11px] text-[#707070]">Prohibited algorithms</p>
        </div>
        <div className="col-span-2 apple-card p-4 sm:col-span-1 border-[#0071e3]/30 bg-[#0071e3]/5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#0071e3]">
            Compliance Index
          </p>
          <p className="font-display mt-2 text-3xl font-semibold tracking-tight text-[#0071e3]">
            {stats.score}%
          </p>
          <p className="mt-1 text-[11px] text-[#707070]">Observed pass ratio</p>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="apple-card p-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-semibold text-[#707070] mr-1">Domain:</span>
          <button
            type="button"
            onClick={() => setSelectedDomain("all")}
            className={`rounded-full px-3 py-1 text-xs font-medium tracking-tight transition ${
              selectedDomain === "all"
                ? "bg-[#1d1d1f] text-white shadow-sm"
                : "bg-[#f5f5f7] text-[#707070] hover:bg-[#e6e6e8] hover:text-[#1d1d1f]"
            }`}
          >
            All
          </button>
          {domains.map((dom) => (
            <button
              key={dom}
              type="button"
              onClick={() => setSelectedDomain(dom)}
              className={`rounded-full px-3 py-1 text-xs font-medium tracking-tight transition ${
                selectedDomain === dom
                  ? "bg-[#1d1d1f] text-white shadow-sm"
                  : "bg-[#f5f5f7] text-[#707070] hover:bg-[#e6e6e8] hover:text-[#1d1d1f]"
              }`}
            >
              {dom}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs font-medium text-[#707070]">
            Verdict:
            <select
              value={selectedVerdict}
              onChange={(e) => setSelectedVerdict(e.target.value)}
              className="rounded-full border border-[#d6d6d6] bg-white px-3 py-1 text-xs text-[#1d1d1f] outline-none focus:border-[#0071e3]"
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
            className="rounded-full border border-[#d6d6d6] bg-white px-3.5 py-1 text-xs text-[#1d1d1f] placeholder:text-[#86868b] focus:border-[#0071e3] focus:outline-none"
          />
        </div>
      </div>

      {/* Compliance Table */}
      <div className="apple-card overflow-x-auto p-6">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-[#e6e6e8] text-[11px] font-semibold uppercase tracking-wider text-[#707070]">
            <tr>
              <th className="pb-3 pr-4">Standard & Algorithm</th>
              <th className="pb-3 pr-4">Domain</th>
              <th className="pb-3 pr-4">RFC Citation</th>
              <th className="pb-3 pr-4">Standard Level</th>
              <th className="pb-3 pr-4">Observed in Capture</th>
              <th className="pb-3">Verdict</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#f5f5f7]">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-[#707070]">
                  No standards match the selected filters.
                </td>
              </tr>
            ) : (
              filtered.map((item) => {
                const isExpanded = expandedId === item.id;
                const v = item.result.verdict;

                let verdictBg = "bg-[#f5f5f7] text-[#707070] border-[#e6e6e8]";
                let verdictIcon = "—";
                let verdictLabel = "NOT OBSERVED";

                if (v === "compliant") {
                  verdictBg = "bg-[#0071e3]/10 text-[#0071e3] border-[#0071e3]/30";
                  verdictIcon = "✓";
                  verdictLabel = "COMPLIANT";
                } else if (v === "warning") {
                  verdictBg = "bg-[#ff9500]/10 text-[#ff9500] border-[#ff9500]/30";
                  verdictIcon = "▲";
                  verdictLabel = "LEGACY / WARN";
                } else if (v === "non-compliant") {
                  verdictBg = "bg-[#d70015]/10 text-[#d70015] border-[#d70015]/30";
                  verdictIcon = "✗";
                  verdictLabel = "VIOLATION";
                }

                let reqClass = "text-[#707070]";
                if (item.requirement === "MUST") reqClass = "text-[#0071e3] font-bold";
                else if (item.requirement === "MUST NOT") reqClass = "text-[#d70015] font-bold";

                return (
                  <tr
                    key={item.id}
                    onClick={() => setExpandedId(isExpanded ? null : item.id)}
                    className="cursor-pointer transition-colors hover:bg-[#fafafc]"
                  >
                    <td className="py-3.5 pr-4">
                      <div className="font-semibold text-[#1d1d1f]">{item.title}</div>
                      <div className="mono text-[11px] text-[#707070]">{item.algorithm}</div>
                    </td>
                    <td className="py-3.5 pr-4">
                      <span className="inline-block rounded-full border border-[#e6e6e8] bg-[#ffffff] px-2.5 py-0.5 text-[10px] font-medium text-[#707070]">
                        {item.domain}
                      </span>
                    </td>
                    <td className="py-3.5 pr-4">
                      <a
                        href={item.rfcUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="mono inline-flex items-center gap-1 font-semibold text-[#0066cc] underline hover:text-[#0077ed]"
                      >
                        {item.rfc}
                        <svg
                          className="h-3 w-3"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                          />
                        </svg>
                      </a>
                      <div className="text-[10px] text-[#707070]">{item.nistRef}</div>
                    </td>
                    <td className="py-3.5 pr-4">
                      <span className={`text-xs ${reqClass}`}>{item.requirement}</span>
                    </td>
                    <td className="py-3.5 pr-4">
                      {item.result.observed ? (
                        <div className="mono font-semibold text-[#1d1d1f]">
                          {item.result.observedValue ?? "Detected"}
                        </div>
                      ) : (
                        <span className="text-[#86868b] italic">Not observable</span>
                      )}
                    </td>
                    <td className="py-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold tracking-wider ${verdictBg}`}
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
        <div className="apple-card p-6 border-[#0071e3]/30 bg-[#fafafc] transition-all">
          {(() => {
            const item = evaluations.find((e) => e.id === expandedId);
            if (!item) return null;
            return (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-display text-base font-semibold text-[#1d1d1f]">
                    {item.title} ({item.algorithm})
                  </h4>
                  <button
                    type="button"
                    onClick={() => setExpandedId(null)}
                    className="text-xs text-[#707070] hover:text-[#1d1d1f]"
                  >
                    ✕ Close details
                  </button>
                </div>
                <p className="text-xs leading-relaxed text-[#1d1d1f]">{item.description}</p>
                <div className="rounded-xl bg-white border border-[#e6e6e8] p-3 text-xs">
                  <span className="font-semibold text-[#0071e3]">Audit Evaluation Note: </span>
                  <span className="text-[#1d1d1f]">{item.result.notes}</span>
                </div>
                <div className="flex flex-wrap gap-4 text-[11px] text-[#707070] pt-1">
                  <span>
                    Requirement: <strong className="text-[#1d1d1f]">{item.requirement}</strong>
                  </span>
                  <span>
                    Specification: <strong className="text-[#1d1d1f]">{item.rfc}</strong>
                  </span>
                  <span>
                    Authority Guideline: <strong className="text-[#1d1d1f]">{item.nistRef}</strong>
                  </span>
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
