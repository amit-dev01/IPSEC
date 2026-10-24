import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";

import {
  ApiError,
  createAnalysis,
  deleteCapture,
  downloadCapture,
  getCapture,
  listCaptureAnalyses,
} from "@/api/client";
import { useToast } from "@/app/toast-context";
import { UnknownValue } from "@/components/epistemic";
import { Skeleton, StatusPill } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";
import ManifestPanel from "@/features/manifest/ManifestPanel";
import { formatBytes, formatTimestamp } from "@/lib/format";

export default function CaptureDetailPage(): ReactNode {
  const { captureId = "" } = useParams();
  const { organizationId } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const captureQuery = useQuery({
    queryKey: ["org", organizationId, "captures", captureId],
    queryFn: ({ signal }) => getCapture(captureId, { signal }),
    enabled: organizationId !== null && captureId !== "",
  });
  const analysesQuery = useQuery({
    queryKey: ["org", organizationId, "captures", captureId, "analyses", { limit: 50 }],
    queryFn: ({ signal }) => listCaptureAnalyses(captureId, { limit: 50 }, { signal }),
    enabled: organizationId !== null && captureId !== "",
  });

  const runMutation = useMutation({
    mutationFn: () => createAnalysis(captureId),
    onSuccess: async (run) => {
      toast.push("success", "Analysis queued.");
      await queryClient.invalidateQueries({
        queryKey: ["org", organizationId, "captures", captureId, "analyses"],
      });
      void navigate(`/analyses/${run.id}`);
    },
    onError: (error: Error) =>
      toast.push(
        "error",
        error instanceof ApiError ? error.userMessage() : "Could not start analysis.",
      ),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteCapture(captureId),
    onSuccess: async () => {
      toast.push("success", "Capture deleted.");
      await queryClient.invalidateQueries({
        queryKey: ["org", organizationId, "captures"],
      });
      void navigate("/captures");
    },
    onError: (error: Error) =>
      toast.push("error", error instanceof ApiError ? error.userMessage() : "Delete failed."),
  });

  if (captureQuery.isPending) return <Skeleton label="Loading capture" rows={4} />;
  if (captureQuery.isError || captureQuery.data === undefined) {
    return (
      <p role="alert" className="text-sm text-sev-critical">
        Capture not found or not accessible in this organization.{" "}
        {captureQuery.error instanceof ApiError ? captureQuery.error.userMessage() : ""}
      </p>
    );
  }
  const capture = captureQuery.data;

  return (
    <section aria-labelledby="capture-heading">
      <p className="text-sm text-ink-muted">
        <Link to="/captures" className="underline">
          ← Capture Vault
        </Link>
      </p>
      <h1 id="capture-heading" className="mt-1 break-all text-xl font-semibold">
        {capture.display_name}
      </h1>

      <dl className="mt-4 grid gap-3 text-sm md:grid-cols-2">
        <div className="rounded border border-line p-3">
          <dt className="font-medium">Metadata</dt>
          <dd className="mt-1 space-y-1">
            <p>
              Format: {capture.format} · State: {capture.state}
            </p>
            <p className="tnum">
              Size: {formatBytes(capture.size_bytes)} ({capture.size_bytes.toLocaleString()} bytes)
            </p>
            <p>Uploaded: {formatTimestamp(capture.uploaded_at)}</p>
            <p>
              Retention expiry:{" "}
              <UnknownValue reason="Retention is enforced server-side; the API does not expose the expiry timestamp." />
            </p>
          </dd>
        </div>
        <div className="rounded border border-line p-3">
          <dt className="font-medium">Integrity</dt>
          <dd className="mt-1 space-y-1">
            <p className="mono break-all">SHA-256 (server-computed at ingest): {capture.sha256}</p>
            <button
              type="button"
              className="rounded border border-line px-2 py-1 text-xs"
              onClick={() => {
                void navigator.clipboard
                  .writeText(capture.sha256)
                  .then(() => toast.push("success", "Full SHA-256 copied."))
                  .catch(() => toast.push("error", "Clipboard copy failed."));
              }}
            >
              Copy full SHA-256
            </button>
            <p className="text-xs text-ink-muted">
              The server streams the upload and computes this digest; the browser never hashes the
              whole file.
            </p>
          </dd>
        </div>
      </dl>

      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          className="rounded border border-line px-3 py-1.5 text-sm"
          onClick={() =>
            void downloadCapture(captureId).catch((error: unknown) =>
              toast.push(
                "error",
                error instanceof ApiError ? error.userMessage() : "Download failed.",
              ),
            )
          }
        >
          Download capture
        </button>
        <RequireAction action="analyses:run">
          <button
            type="button"
            disabled={runMutation.isPending}
            onClick={() => runMutation.mutate()}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink disabled:opacity-50"
          >
            Run Security Analysis
          </button>
        </RequireAction>
        <RequireAction action="captures:delete">
          <button
            type="button"
            className="rounded border border-line px-3 py-1.5 text-sm"
            onClick={() => {
              if (
                window.confirm(
                  `Delete capture "${capture.display_name}"? This permanently removes the stored capture and its analysis history. Retention/audit records may keep the deletion event.`,
                )
              ) {
                deleteMutation.mutate();
              }
            }}
          >
            Delete capture
          </button>
        </RequireAction>
      </div>
      <p className="mt-2 text-xs text-ink-muted">
        The backend always applies its configured assessment policy (this API takes no client policy
        profile); the run records the applied <span className="mono">policy_version</span>.
      </p>

      <ManifestPanel captureId={captureId} />

      <h2 className="mt-8 text-lg font-medium">Analysis history</h2>
      {analysesQuery.isPending && <Skeleton label="Loading analysis history" rows={3} />}
      {analysesQuery.isSuccess && (analysesQuery.data.items.length ?? 0) === 0 && (
        <p className="mt-2 text-sm text-ink-muted">No analyses have run for this capture yet.</p>
      )}
      <ul className="mt-2 space-y-2">
        {(analysesQuery.data?.items ?? []).map((run) => (
          <li
            key={run.id}
            className="flex flex-wrap items-center gap-3 rounded border border-line px-3 py-2 text-sm"
          >
            <StatusPill status={run.status} />
            <Link to={`/analyses/${run.id}`} className="mono underline">
              {run.id}
            </Link>
            <span className="text-ink-muted">
              queued {formatTimestamp(run.queued_at)} · policy {run.policy_version} · pipeline{" "}
              {run.pipeline_version}
            </span>
            <span className="tnum ml-auto">
              {run.risk_score !== null ? `risk ${run.risk_score} / 100` : "not scored"}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
