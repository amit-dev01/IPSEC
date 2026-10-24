import type { ReactNode } from "react";
import { useState } from "react";
import { Link } from "react-router";

import { ApiError, downloadFile } from "@/api/client";

export default function AdminPage(): ReactNode {
  const [message, setMessage] = useState<string | null>(null);
  return (
    <section aria-labelledby="admin-heading">
      <h1 id="admin-heading" className="text-xl font-semibold">
        Governance &amp; Administration
      </h1>
      <p className="mt-2 max-w-prose text-sm text-ink-muted">
        Administrator-only governance tools. Every action is enforced and audited by the backend;
        this UI is not the authorization boundary.
      </p>

      <ul className="mt-4 space-y-2 text-sm">
        <li className="rounded border border-line p-3">
          <Link to="/admin/audit" className="font-medium underline">
            Tamper-Evident Audit Trail
          </Link>
          <p className="mt-1 text-ink-muted">
            Paginated, filterable audit events with a hash-chain indicator (tamper-evident log — not
            a public blockchain).
          </p>
        </li>
        <li className="rounded border border-line p-3">
          <Link to="/admin/live-capture" className="font-medium underline">
            Passive Capture Agent
          </Link>
          <p className="mt-1 text-ink-muted">
            Strictly bounded, administrator-allowlisted passive capture triggers. No free-text
            interfaces, flags, paths, or filters. Shows a disabled status card when the optional
            agent is not enabled.
          </p>
        </li>
      </ul>

      <h2 className="mt-6 font-medium">De-identified dataset export</h2>
      <p className="mt-1 max-w-prose text-sm text-ink-muted">
        Flow-metadata features and lab labels only. No PCAPs, no credentials, no endpoint
        identifiers. The backend audits this export.
      </p>
      <button
        type="button"
        className="mt-3 rounded bg-accent px-3 py-2 text-sm font-medium text-accent-ink"
        onClick={() =>
          void downloadFile("/api/v1/admin/exports/flow-dataset", "flow-dataset.json")
            .then(() => setMessage("Export downloaded."))
            .catch((error: unknown) =>
              setMessage(error instanceof ApiError ? error.detail : "Export failed."),
            )
        }
      >
        Export de-identified flow dataset
      </button>
      {message !== null && (
        <p role="status" className="mt-3 text-sm">
          {message}
        </p>
      )}
    </section>
  );
}
