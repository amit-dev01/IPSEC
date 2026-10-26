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
    <section aria-labelledby="capture-heading" className="space-y-6">
      <div>
        <p className="text-xs font-medium text-[#707070]">
          <Link to="/captures" className="text-[#0066cc] hover:underline">
            ← Capture Vault
          </Link>
        </p>
        <h1
          id="capture-heading"
          className="font-display mt-2 break-all text-2xl font-semibold tracking-tight text-[#1d1d1f] md:text-3xl"
        >
          {capture.display_name}
        </h1>
      </div>

      <dl className="grid gap-4 md:grid-cols-2">
        <div className="apple-card p-6">
          <dt className="font-display text-base font-semibold text-[#1d1d1f]">Capture Metadata</dt>
          <dd className="mt-3 space-y-2 text-sm text-[#707070]">
            <p className="text-[#1d1d1f]">
              Format:{" "}
              <span className="font-semibold uppercase tracking-wider">{capture.format}</span> ·
              State:{" "}
              <span className="inline-flex rounded-full border border-[#e6e6e8] bg-[#ffffff] px-2.5 py-0.5 text-xs font-medium text-[#1d1d1f]">
                {capture.state}
              </span>
            </p>
            <p className="tnum">
              Size: <strong className="text-[#1d1d1f]">{formatBytes(capture.size_bytes)}</strong> (
              {capture.size_bytes.toLocaleString()} bytes)
            </p>
            <p>
              Uploaded:{" "}
              <span className="text-[#1d1d1f]">{formatTimestamp(capture.uploaded_at)}</span>
            </p>
            <div className="pt-1">
              <span className="text-xs text-[#707070] block mb-1">Retention policy:</span>
              <UnknownValue reason="Retention is enforced server-side; the API does not expose the expiry timestamp." />
            </div>
          </dd>
        </div>

        <div className="apple-card p-6">
          <dt className="font-display text-base font-semibold text-[#1d1d1f]">
            Ingest Cryptographic Integrity
          </dt>
          <dd className="mt-3 space-y-2 text-sm">
            <p className="mono break-all text-xs text-[#1d1d1f]">
              SHA-256: <span className="font-semibold">{capture.sha256}</span>
            </p>
            <button
              type="button"
              className="apple-btn-secondary text-xs"
              onClick={() => {
                void navigator.clipboard
                  .writeText(capture.sha256)
                  .then(() => toast.push("success", "Full SHA-256 copied."))
                  .catch(() => toast.push("error", "Clipboard copy failed."));
              }}
            >
              Copy full SHA-256
            </button>
            <p className="text-xs text-[#707070] pt-1">
              The server streams the upload and computes this digest; the browser never hashes the
              whole file.
            </p>
          </dd>
        </div>
      </dl>

      <div className="flex flex-wrap items-center gap-3">
        <RequireAction action="analyses:run">
          <button
            type="button"
            disabled={runMutation.isPending}
            onClick={() => runMutation.mutate()}
            className="apple-btn-primary disabled:opacity-50"
          >
            Run Security Analysis
          </button>
        </RequireAction>
        <button
          type="button"
          className="apple-btn-secondary"
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
        <RequireAction action="captures:delete">
          <button
            type="button"
            className="apple-btn-secondary text-[#d70015] hover:border-[#d70015]/40"
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

      <p className="text-xs text-[#707070]">
        The backend always applies its configured assessment policy (this API takes no client policy
        profile); the run records the applied{" "}
        <span className="mono font-semibold">{capture.state}</span>.
      </p>

      <ManifestPanel captureId={captureId} />

      <div className="space-y-4 pt-4">
        <h2 className="font-display text-xl font-semibold text-[#1d1d1f]">Analysis History</h2>
        {analysesQuery.isPending && <Skeleton label="Loading analysis history" rows={3} />}
        {analysesQuery.isSuccess && (analysesQuery.data.items.length ?? 0) === 0 && (
          <p className="text-sm text-[#707070]">No analyses have run for this capture yet.</p>
        )}
        <ul className="space-y-2">
          {(analysesQuery.data?.items ?? []).map((run) => (
            <li
              key={run.id}
              className="apple-card flex flex-wrap items-center gap-4 p-4 text-sm transition hover:border-[#d6d6d6]"
            >
              <StatusPill status={run.status} />
              <Link
                to={`/analyses/${run.id}`}
                className="mono font-semibold text-[#0066cc] hover:underline"
              >
                {run.id}
              </Link>
              <span className="text-xs text-[#707070]">
                queued {formatTimestamp(run.queued_at)} · policy{" "}
                <span className="mono">{run.policy_version}</span> · pipeline{" "}
                <span className="mono">{run.pipeline_version}</span>
              </span>
              <span className="tnum ml-auto font-semibold text-[#1d1d1f]">
                {run.risk_score !== null ? `risk ${run.risk_score} / 100` : "not scored"}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
