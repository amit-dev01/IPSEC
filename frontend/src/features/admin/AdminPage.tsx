import type { ReactNode } from "react";
import { useState } from "react";

import { ApiError, downloadFile } from "@/api/client";

export default function AdminPage(): ReactNode {
  const [message, setMessage] = useState<string | null>(null);
  return (
    <section aria-labelledby="admin-heading">
      <h1 id="admin-heading" className="text-xl font-semibold">
        Administration
      </h1>
      <p className="mt-2 max-w-prose text-sm text-ink-muted">
        De-identified dataset export: flow-metadata features and lab labels only. No PCAPs, no
        credentials, no endpoint identifiers. The backend audits this export.
      </p>
      <button
        type="button"
        className="mt-4 rounded bg-accent px-3 py-2 text-sm font-medium text-accent-ink"
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
      <p className="mt-6 max-w-prose text-sm text-ink-muted">
        Audit trail review and allowlisted passive-agent controls are admin capabilities enforced by
        the backend; their dedicated screens are a later stage. Audit events are recorded by the
        backend for uploads, downloads, deletions, analysis creation, and report generation.
      </p>
    </section>
  );
}
