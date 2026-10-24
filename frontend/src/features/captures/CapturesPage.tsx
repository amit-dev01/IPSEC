import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ChangeEvent, ReactNode } from "react";
import { useRef, useState } from "react";

import {
  ApiError,
  createAnalysis,
  deleteCapture,
  downloadFile,
  listCaptures,
  uploadCapture,
} from "@/api/client";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";
import { formatBytes, formatTimestamp } from "@/lib/format";
import { sniffCaptureKind } from "@/lib/files";

export default function CapturesPage(): ReactNode {
  const { organizationId, role } = useAuth();
  const queryClient = useQueryClient();
  const [uploadState, setUploadState] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const capturesQuery = useQuery({
    queryKey: ["org", organizationId, "captures", { limit: 50, offset: 0 }],
    queryFn: ({ signal }) => listCaptures({ limit: 50, offset: 0 }, { signal }),
    enabled: organizationId !== null,
  });

  const invalidate = async (): Promise<void> => {
    await queryClient.invalidateQueries({ queryKey: ["org", organizationId, "captures"] });
  };

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteCapture(id),
    onSuccess: invalidate,
    onError: (error) => setPageError(error instanceof ApiError ? error.detail : "Delete failed."),
  });

  const analyzeMutation = useMutation({
    mutationFn: (id: string) => createAnalysis(id),
    onSuccess: invalidate,
    onError: (error) =>
      setPageError(error instanceof ApiError ? error.detail : "Could not start analysis."),
  });

  async function onFileSelected(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file === undefined) return;
    setPageError(null);
    // Pre-validation only (first 16 bytes). Backend validation is authoritative.
    const kind = await sniffCaptureKind(file);
    if (kind === "unknown") {
      setPageError(
        "That file does not start with PCAP/PCAPNG magic bytes. The server performs the authoritative validation.",
      );
      return;
    }
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      await uploadCapture(file, {
        signal: controller.signal,
        onProgress: (loaded, total) =>
          setUploadState(
            total !== null
              ? `Uploading ${formatBytes(loaded)} of ${formatBytes(total)}`
              : `Uploading ${formatBytes(loaded)}`,
          ),
      });
      setUploadState("Upload complete. Server-computed SHA-256 is shown in the list.");
      await invalidate();
    } catch (error) {
      setPageError(error instanceof ApiError ? error.detail : "Upload failed.");
    } finally {
      setUploadState(null);
      abortRef.current = null;
    }
  }

  const captures = capturesQuery.data?.items ?? [];

  return (
    <section aria-labelledby="captures-heading">
      <div className="flex flex-wrap items-center gap-3">
        <h1 id="captures-heading" className="text-xl font-semibold">
          Captures
        </h1>
        <RequireAction action="captures:upload">
          <label className="cursor-pointer rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink">
            Upload capture
            <input
              type="file"
              accept=".pcap,.pcapng"
              className="sr-only"
              aria-label="Upload capture file"
              onChange={(e) => void onFileSelected(e)}
            />
          </label>
        </RequireAction>
        <span className="text-xs text-ink-muted">
          Signed in as {role}. Server enforces upload limits and validation.
        </span>
      </div>

      {uploadState !== null && (
        <p role="status" className="mt-3 text-sm">
          {uploadState}{" "}
          <button type="button" className="underline" onClick={() => abortRef.current?.abort()}>
            Cancel upload
          </button>
        </p>
      )}
      {pageError !== null && (
        <p
          role="alert"
          className="mt-3 rounded border border-sev-critical px-3 py-2 text-sm text-sev-critical"
        >
          {pageError}
        </p>
      )}

      {capturesQuery.isPending && <p className="mt-4 text-sm">Loading captures…</p>}
      {capturesQuery.isError && (
        <p role="alert" className="mt-4 text-sm text-sev-critical">
          Could not load captures.
        </p>
      )}
      {capturesQuery.isSuccess && captures.length === 0 && (
        <p className="mt-4 text-sm text-ink-muted">No captures yet for this organization.</p>
      )}

      {captures.length > 0 && (
        <table className="mt-4 w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-line text-left">
              <th scope="col" className="py-2 pr-3">
                Name
              </th>
              <th scope="col" className="py-2 pr-3">
                SHA-256 (server)
              </th>
              <th scope="col" className="py-2 pr-3">
                Size
              </th>
              <th scope="col" className="py-2 pr-3">
                Format
              </th>
              <th scope="col" className="py-2 pr-3">
                Uploaded
              </th>
              <th scope="col" className="py-2">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {captures.map((capture) => (
              <tr key={capture.id} className="border-b border-line">
                <td className="py-2 pr-3">{capture.display_name}</td>
                <td className="mono py-2 pr-3">{capture.sha256}</td>
                <td className="tnum py-2 pr-3">{formatBytes(capture.size_bytes)}</td>
                <td className="py-2 pr-3">{capture.format}</td>
                <td className="py-2 pr-3">{formatTimestamp(capture.uploaded_at)}</td>
                <td className="py-2">
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="underline"
                      onClick={() =>
                        void downloadFile(
                          `/api/v1/captures/${capture.id}/download`,
                          capture.display_name,
                        ).catch((error: unknown) =>
                          setPageError(
                            error instanceof ApiError ? error.detail : "Download failed.",
                          ),
                        )
                      }
                    >
                      Download
                    </button>
                    <RequireAction action="analyses:run">
                      <button
                        type="button"
                        className="underline"
                        onClick={() => analyzeMutation.mutate(capture.id)}
                      >
                        Analyze
                      </button>
                    </RequireAction>
                    <RequireAction action="captures:delete">
                      <button
                        type="button"
                        className="underline"
                        onClick={() => deleteMutation.mutate(capture.id)}
                      >
                        Delete
                      </button>
                    </RequireAction>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
