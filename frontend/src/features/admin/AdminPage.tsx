import type { ReactNode } from "react";
import { useState } from "react";
import { Link } from "react-router";

import { ApiError, downloadFile } from "@/api/client";

export default function AdminPage(): ReactNode {
  const [message, setMessage] = useState<string | null>(null);
  return (
    <section aria-labelledby="admin-heading" className="space-y-6">
      <div>
        <h1
          id="admin-heading"
          className="font-display text-2xl font-semibold tracking-tight text-[#1d1d1f]"
        >
          Governance &amp; Administration
        </h1>
        <p className="mt-1 max-w-prose text-xs text-[#707070]">
          Administrator-only governance tools. Every action is strictly enforced and audited
          server-side; this UI does not represent the authorization boundary.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="apple-card p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-[#0071e3]/10 text-[#0071e3]">
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </span>
              <h2 className="font-display text-base font-semibold text-[#1d1d1f]">
                Tamper-Evident Audit Trail
              </h2>
            </div>
            <p className="mt-2 text-xs text-[#707070] leading-relaxed">
              Paginated, filterable audit events with SHA-256 hash-chain verification
              (tamper-evident log — not a public blockchain).
            </p>
          </div>
          <div className="mt-4 pt-4 border-t border-[#e6e6e8]">
            <Link
              to="/admin/audit"
              className="apple-btn-secondary text-xs inline-flex items-center gap-1.5"
            >
              Launch Audit Inspector
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
            </Link>
          </div>
        </div>

        <div className="apple-card p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-[#34c759]/10 text-[#34c759]">
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M13 10V3L4 14h7v7l9-11h-7z"
                  />
                </svg>
              </span>
              <h2 className="font-display text-base font-semibold text-[#1d1d1f]">
                Passive Capture Agent
              </h2>
            </div>
            <p className="mt-2 text-xs text-[#707070] leading-relaxed">
              Strictly bounded, administrator-allowlisted passive capture triggers. No free-text
              interfaces, flags, paths, or filters.
            </p>
          </div>
          <div className="mt-4 pt-4 border-t border-[#e6e6e8]">
            <Link
              to="/admin/live-capture"
              className="apple-btn-secondary text-xs inline-flex items-center gap-1.5"
            >
              Launch Agent Console
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
            </Link>
          </div>
        </div>
      </div>

      <div className="apple-card p-6 space-y-3">
        <div>
          <h2 className="font-display text-base font-semibold text-[#1d1d1f]">
            De-Identified Flow Dataset Export
          </h2>
          <p className="mt-1 max-w-prose text-xs text-[#707070]">
            Export sanitized flow-metadata features and lab labels only. No PCAPs, no credentials,
            no endpoint identifiers. The backend audits each export operation.
          </p>
        </div>
        <div>
          <button
            type="button"
            className="apple-btn-primary text-xs"
            onClick={() =>
              void downloadFile("/api/v1/admin/exports/flow-dataset", "flow-dataset.json")
                .then(() => setMessage("Export downloaded successfully."))
                .catch((error: unknown) =>
                  setMessage(error instanceof ApiError ? error.detail : "Export failed."),
                )
            }
          >
            Export De-Identified Flow Dataset
          </button>
        </div>
        {message !== null && (
          <p
            role="status"
            className="rounded-full border border-[#e6e6e8] bg-[#fafafc] px-3 py-1 text-xs text-[#1d1d1f] inline-block"
          >
            {message}
          </p>
        )}
      </div>
    </section>
  );
}
