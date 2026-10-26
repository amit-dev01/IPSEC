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
    <section aria-labelledby="captures-heading" className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1
            id="captures-heading"
            className="font-display text-3xl font-semibold tracking-tight text-[#1d1d1f]"
          >
            Capture Vault
          </h1>
          <p className="mt-1 text-sm text-[#707070]">
            Immutable enterprise PCAP and PCAPNG ingest with streaming cryptographic digests.
          </p>
        </div>
        <RequireAction action="captures:upload">
          <button
            type="button"
            onClick={() => setUploadOpen(true)}
            className="apple-btn-primary text-sm"
          >
            Upload Capture
          </button>
        </RequireAction>
      </div>

      <fieldset className="flex flex-wrap items-center gap-3">
        <legend className="sr-only">Filter captures</legend>
        <label className="flex items-center gap-2 text-xs font-medium text-[#707070]">
          State
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(0);
            }}
            className="rounded-full border border-[#d6d6d6] bg-white px-3 py-1 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
          >
            <option value="">All States</option>
            <option value="available">available</option>
            <option value="queued">queued</option>
            <option value="processing">processing</option>
            <option value="failed">failed</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs font-medium text-[#707070]">
          Format
          <select
            value={formatFilter}
            onChange={(e) => {
              setFormatFilter(e.target.value);
              setPage(0);
            }}
            className="rounded-full border border-[#d6d6d6] bg-white px-3 py-1 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
          >
            <option value="">All Formats</option>
            <option value="pcap">pcap</option>
            <option value="pcapng">pcapng</option>
          </select>
        </label>
      </fieldset>

      {listQuery.isPending && <Skeleton label="Loading captures" rows={4} />}
      {listQuery.isError && (
        <p role="alert" className="text-sm font-medium text-[#d70015]">
          Could not load captures.{" "}
          {listQuery.error instanceof ApiError ? listQuery.error.userMessage() : ""}
        </p>
      )}

      {listQuery.isSuccess && items.length === 0 && (
        <div className="mt-4">
          <EmptyState title="No captures match">
            <p>Upload an authorized PCAP/PCAPNG capture, or clear the filters above.</p>
          </EmptyState>
        </div>
      )}

      {items.length > 0 && (
        <div className="apple-card overflow-x-auto p-6">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[#e6e6e8] text-[11px] font-semibold uppercase tracking-wider text-[#707070]">
                <th scope="col" className="pb-3 pr-4">
                  Name
                </th>
                <th scope="col" className="pb-3 pr-4">
                  Format
                </th>
                <th scope="col" className="pb-3 pr-4">
                  Size
                </th>
                <th scope="col" className="pb-3 pr-4">
                  SHA-256
                </th>
                <th scope="col" className="pb-3 pr-4">
                  Uploaded
                </th>
                <th scope="col" className="pb-3 pr-4">
                  Retention
                </th>
                <th scope="col" className="pb-3 pr-4">
                  State
                </th>
                <th scope="col" className="pb-3 pr-4">
                  Analyses
                </th>
                <th scope="col" className="pb-3">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#f5f5f7]">
              {items.map((capture, index) => (
                <tr key={capture.id} className="align-middle transition hover:bg-[#fafafc]">
                  <td className="py-3.5 pr-4">
                    <Link
                      to={`/captures/${capture.id}`}
                      className="font-semibold text-[#0066cc] hover:underline"
                    >
                      {capture.display_name}
                    </Link>
                  </td>
                  <td className="py-3.5 pr-4 text-[#1d1d1f] uppercase tracking-wider">
                    {capture.format}
                  </td>
                  <td className="tnum py-3.5 pr-4 text-[#1d1d1f]">
                    {formatBytes(capture.size_bytes)}{" "}
                    <span className="text-[#707070]">
                      ({capture.size_bytes.toLocaleString()} B)
                    </span>
                  </td>
                  <td className="mono py-3.5 pr-4 text-xs text-[#1d1d1f]">
                    {capture.sha256.slice(0, 12)}…{" "}
                    <button
                      type="button"
                      aria-label={`Copy full SHA-256 for ${capture.display_name}`}
                      onClick={() => void copyHash(capture.sha256)}
                      className="ml-1 rounded-full border border-[#d6d6d6] px-2 py-0.5 text-[10px] text-[#707070] hover:text-[#1d1d1f] hover:bg-[#f5f5f7]"
                    >
                      Copy
                    </button>
                  </td>
                  <td className="py-3.5 pr-4 text-[#707070]">
                    {formatTimestamp(capture.uploaded_at)}
                  </td>
                  <td className="py-3.5 pr-4">
                    <UnknownValue reason="Retention expiry is enforced server-side and is not exposed by the API." />
                  </td>
                  <td className="py-3.5 pr-4">
                    <span className="inline-flex rounded-full border border-[#e6e6e8] bg-[#ffffff] px-2.5 py-0.5 text-xs font-medium text-[#1d1d1f]">
                      {capture.state}
                    </span>
                  </td>
                  <td className="tnum py-3.5 pr-4 font-semibold text-[#1d1d1f]">
                    {countQueries[index]?.data?.total ?? "…"}
                  </td>
                  <td className="py-3.5">
                    <span className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => downloadMutation.mutate(capture.id)}
                        className="apple-btn-secondary px-3 py-1 text-xs"
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
                          className="apple-btn-secondary px-3 py-1 text-xs text-[#d70015] hover:border-[#d70015]/40"
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
        </div>
      )}

      <nav
        aria-label="Capture pages"
        className="flex items-center justify-between text-xs font-medium text-[#707070]"
      >
        <button
          type="button"
          disabled={page === 0}
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          className="apple-btn-secondary px-4 py-1.5 text-xs disabled:opacity-40"
        >
          Previous
        </button>
        <span className="tnum text-xs">
          Page {page + 1} · {total} total captures
        </span>
        <button
          type="button"
          disabled={offset + PAGE_SIZE >= total}
          onClick={() => setPage((p) => p + 1)}
          className="apple-btn-secondary px-4 py-1.5 text-xs disabled:opacity-40"
        >
          Next
        </button>
      </nav>

      {uploadOpen && (
        <UploadModal
          onClose={() => setUploadOpen(false)}
          onUploaded={async () => {
            // Do NOT close here: the modal shows the authoritative
            // server-computed SHA-256 on completion; the user dismisses
            // it with Done. (Auto-closing hid that confirmation.)
            await invalidateLists();
          }}
        />
      )}
    </section>
  );
}
