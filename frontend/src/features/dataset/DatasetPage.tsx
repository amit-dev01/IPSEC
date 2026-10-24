import type { ReactNode } from "react";

import { ApiError, exportDataset } from "@/api/client";
import { useToast } from "@/app/toast-context";
import { useAuth } from "@/features/auth/auth-context";

export default function DatasetPage(): ReactNode {
  const { role } = useAuth();
  const toast = useToast();

  return (
    <section aria-labelledby="dataset-heading">
      <h1 id="dataset-heading" className="text-xl font-semibold">
        Dataset &amp; Lab
      </h1>
      <p className="mt-2 max-w-3xl text-sm">
        The de-identified dataset export (administrators only; your role: <strong>{role}</strong>)
        contains evidence, findings, and lab-manifest ground truth with endpoint identifiers
        privacy-hashed. It <strong>never</strong> contains raw PCAPs, packet payloads, PSKs, private
        keys, session secrets, tokens, or storage credentials.
      </p>
      <div
        role="note"
        className="mt-3 max-w-3xl rounded border border-line bg-surface-sunken p-3 text-sm"
      >
        <strong>Privacy notice:</strong> exports are generated server-side with tenant scoping and
        de-identification applied before download. Treat exported metadata as sensitive lab data:
        store it under the same controls as the captures it summarizes.
      </div>
      <button
        type="button"
        className="mt-4 rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink"
        onClick={() =>
          void exportDataset().catch((error: unknown) =>
            toast.push(
              "error",
              error instanceof ApiError ? error.userMessage() : "Dataset export failed.",
            ),
          )
        }
      >
        Download de-identified dataset (JSONL)
      </button>
      <p className="mt-3 max-w-3xl text-sm text-ink-muted">
        Lab manifests are attached per capture (Capture detail → Lab Manifest &amp; Ground Truth)
        and reconciled against packet-observed evidence during analysis; discrepancies are flagged
        in the Protocol &amp; Security Inspector.
      </p>
    </section>
  );
}
