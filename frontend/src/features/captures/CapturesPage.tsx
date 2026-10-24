import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";
import { Link } from "react-router";

import {
  ApiError,
  deleteCapture,
  downloadCapture,
  listCaptureAnalyses,
  listCaptures,
} from "@/api/client";
import { useToast } from "@/app/toast-context";
import { UnknownValue } from "@/components/epistemic";
import { Skeleton, EmptyState } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";
import { formatBytes, formatTimestamp } from "@/lib/format";

import UploadModal from "./UploadModal";

const PAGE_SIZE = 20;

export default function CapturesPage(): ReactNode {
  const { organizationId } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [formatFilter, setFormatFilter] = useState<string>("");
  const [uploadOpen, setUploadOpen] = useState(false);
  const offset = page * PAGE_SIZE;

  const queryParams = {
    limit: PAGE_SIZE,
    offset,
    ...(statusFilter !== "" ? { state: statusFilter } : {}),
  };

  const listQuery = useQuery({
    queryKey: ["org", organizationId, "captures", queryParams],
    queryFn: ({ signal }) => listCaptures(queryParams, { signal }),
    enabled: organizationId !== null,
  });

  const allItems = listQuery.data?.items ?? [];
  const items = formatFilter === "" ? allItems : allItems.filter((c) => c.format === formatFilter);
  const total = listQuery.data?.total ?? 0;

  const countQueries = useQueries({
    queries: items.map((capture) => ({
      queryKey: ["org", organizationId, "captures", capture.id, "analyses-count"],
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        listCaptureAnalyses(capture.id, { limit: 1 }, { signal }),
      enabled: organizationId !== null,
    })),
  });

  const invalidateLists = (): Promise<void> =>
    queryClient.invalidateQueries({ queryKey: ["org", organizationId, "captures"] });

  const deleteMutation = useMutation({
    mutationFn: (captureId: string) => deleteCapture(captureId),
    onSuccess: async () => {
      toast.push("success", "Capture deleted.");
      await invalidateLists();
    },
    onError: (error: Error) => {
      toast.push("error", error instanceof ApiError ? error.userMessage() : "Delete failed.");
    },
  });

  const downloadMutation = useMutation({
    mutationFn: (captureId: string) => downloadCapture(captureId),
    onError: (error: Error) => {
      toast.push("error", error instanceof ApiError ? error.userMessage() : "Download failed.");
    },
  });

  const copyHash = async (hash: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(hash);
      toast.push("success", "Full SHA-256 copied to clipboard.");
    } catch {
      toast.push("error", "Clipboard copy failed in this browser.");
    }
  };

  return (
    <section aria-labelledby="captures-heading">
      <div className="flex flex-wrap items-center gap-3">
        <h1 id="captures-heading" className="text-xl font-semibold">
          Capture Vault
        </h1>
        <RequireAction action="captures:upload">
          <button
            type="button"
            onClick={() => setUploadOpen(true)}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink"
          >
            Upload Capture
          </button>
        </RequireAction>
      </div>

      <fieldset className="mt-4 flex flex-wrap gap-3">
        <legend className="sr-only">Filter captures</legend>
        <label className="text-sm">
          State{" "}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(0);
            }}
            className="rounded border border-line px-2 py-1"
          >
            <option value="">All</option>
            <option value="available">available</option>
            <option value="queued">queued</option>
            <option value="processing">processing</option>
            <option value="failed">failed</option>
          </select>
        </label>
        <label className="text-sm">
          Format{" "}
          <select
            value={formatFilter}
            onChange={(e) => {
              setFormatFilter(e.target.value);
              setPage(0);
            }}
            className="rounded border border-line px-2 py-1"
          >
            <option value="">All</option>
            <option value="pcap">pcap</option>
            <option value="pcapng">pcapng</option>
          </select>
        </label>
      </fieldset>

      {listQuery.isPending && <Skeleton label="Loading captures" rows={4} />}
      {listQuery.isError && (
        <p role="alert" className="mt-4 text-sm text-sev-critical">
          Could not load captures.{" "}
          {listQuery.error instanceof ApiError ? listQuery.error.userMessage() : ""}
        </p>
      )}

      {listQuery.isSuccess && items.length === 0 && (
        <div className="mt-6">
          <EmptyState title="No captures match">
            <p>Upload an authorized PCAP/PCAPNG capture, or clear the filters above.</p>
          </EmptyState>
        </div>
      )}

      {items.length > 0 && (
        <table className="mt-4 w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-line text-left">
              <th scope="col" className="py-2 pr-3">
                Name
              </th>
              <th scope="col" className="py-2 pr-3">
                Format
              </th>
              <th scope="col" className="py-2 pr-3">
                Size
              </th>
              <th scope="col" className="py-2 pr-3">
                SHA-256
              </th>
              <th scope="col" className="py-2 pr-3">
                Uploaded
              </th>
              <th scope="col" className="py-2 pr-3">
                Retention
              </th>
              <th scope="col" className="py-2 pr-3">
                State
              </th>
              <th scope="col" className="py-2 pr-3">
                Analyses
              </th>
              <th scope="col" className="py-2">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((capture, index) => (
              <tr key={capture.id} className="border-b border-line align-top">
                <td className="py-2 pr-3">
                  <Link to={`/captures/${capture.id}`} className="underline">
                    {capture.display_name}
                  </Link>
                </td>
                <td className="py-2 pr-3">{capture.format}</td>
                <td className="tnum py-2 pr-3">
                  {formatBytes(capture.size_bytes)}{" "}
                  <span className="text-ink-muted">({capture.size_bytes.toLocaleString()} B)</span>
                </td>
                <td className="mono py-2 pr-3">
                  {capture.sha256.slice(0, 12)}…{" "}
                  <button
                    type="button"
                    aria-label={`Copy full SHA-256 for ${capture.display_name}`}
                    onClick={() => void copyHash(capture.sha256)}
                    className="rounded border border-line px-1 text-xs"
                  >
                    Copy
                  </button>
                </td>
                <td className="py-2 pr-3">{formatTimestamp(capture.uploaded_at)}</td>
                <td className="py-2 pr-3">
                  <UnknownValue reason="Retention expiry is enforced server-side and is not exposed by the API." />
                </td>
                <td className="py-2 pr-3">{capture.state}</td>
                <td className="tnum py-2 pr-3">{countQueries[index]?.data?.total ?? "…"}</td>
                <td className="py-2">
                  <span className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => downloadMutation.mutate(capture.id)}
                      className="rounded border border-line px-2 py-1 text-xs"
                    >
                      Download
                    </button>
                    <RequireAction action="captures:delete">
                      <button
                        type="button"
                        onClick={() => {
                          if (
                            window.confirm(
                              `Delete capture "${capture.display_name}"? This permanently removes the stored capture and its analysis history. Retention/audit records may keep the deletion event.`,
                            )
                          ) {
                            deleteMutation.mutate(capture.id);
                          }
                        }}
                        className="rounded border border-line px-2 py-1 text-xs"
                      >
                        Delete
                      </button>
                    </RequireAction>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <nav aria-label="Capture pages" className="mt-4 flex items-center gap-3 text-sm">
        <button
          type="button"
          disabled={page === 0}
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          className="rounded border border-line px-2 py-1 disabled:opacity-50"
        >
          Previous
        </button>
        <span className="tnum">
          Page {page + 1} · {total} total
        </span>
        <button
          type="button"
          disabled={offset + PAGE_SIZE >= total}
          onClick={() => setPage((p) => p + 1)}
          className="rounded border border-line px-2 py-1 disabled:opacity-50"
        >
          Next
        </button>
      </nav>

      {uploadOpen && (
        <UploadModal
          onClose={() => setUploadOpen(false)}
          onUploaded={async () => {
            setUploadOpen(false);
            await invalidateLists();
          }}
        />
      )}
    </section>
  );
}
