import type { FormEvent, ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import { ApiError, uploadCapture } from "@/api/client";
import { MAX_UPLOAD_BYTES } from "@/lib/config";
import { formatBytes } from "@/lib/format";
import { detectCaptureKind } from "@/lib/files";

interface UploadState {
  kind: "idle" | "uploading" | "done" | "error";
  sentBytes: number;
  totalBytes: number;
  serverSha256: string | null;
  message: string | null;
}

const initialState: UploadState = {
  kind: "idle",
  sentBytes: 0,
  totalBytes: 0,
  serverSha256: null,
  message: null,
};

export default function UploadModal({
  onClose,
  onUploaded,
}: {
  onClose: () => void;
  onUploaded: () => Promise<void>;
}): ReactNode {
  const [file, setFile] = useState<File | null>(null);
  const [precheck, setPrecheck] = useState<string | null>(null);
  const [state, setState] = useState<UploadState>(initialState);
  const abortRef = useRef<AbortController | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);

  // Focus trap: keep Tab cycling inside the dialog, Escape closes, and
  // initial focus lands on the dialog heading region.
  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) return;
    const focusables = (): HTMLElement[] =>
      [
        ...dialog.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ].filter((el) => !el.hasAttribute("disabled"));
    focusables()[0]?.focus();
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusables();
      if (items.length === 0) return;
      const first = items[0]!;
      const last = items[items.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  const oversized = file !== null && file.size > MAX_UPLOAD_BYTES;

  const onFileChosen = async (chosen: File | null): Promise<void> => {
    setFile(chosen);
    setPrecheck(null);
    if (chosen === null) return;
    // Only the first 16 bytes are inspected (Blob.slice); the whole file is
    // never loaded into memory. Server-side magic validation is authoritative.
    const kind = await detectCaptureKind(chosen);
    if (kind === null) {
      setPrecheck(
        "Rejected before upload: the first bytes are not PCAP or PCAPNG magic. " +
          "Extension and MIME type are ignored; rename the file only if it truly is a capture.",
      );
    }
  };

  const onFileInput = async (event: FormEvent<HTMLInputElement>): Promise<void> => {
    const chosen = event.currentTarget.files?.[0] ?? null;
    await onFileChosen(chosen);
  };

  const startUpload = async (): Promise<void> => {
    if (file === null || precheck !== null || oversized) return;
    const controller = new AbortController();
    abortRef.current = controller;
    setState({
      kind: "uploading",
      sentBytes: 0,
      totalBytes: file.size,
      serverSha256: null,
      message: null,
    });
    try {
      const capture = await uploadCapture(file, {
        signal: controller.signal,
        onProgress: (sent, total) =>
          setState((s) => ({ ...s, sentBytes: sent, totalBytes: total ?? s.totalBytes })),
      });
      setState({
        kind: "done",
        sentBytes: file.size,
        totalBytes: file.size,
        serverSha256: capture.sha256,
        message: `Uploaded "${capture.display_name}" (${capture.format}).`,
      });
      await onUploaded();
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        setState({ ...initialState, message: "Upload cancelled by user." });
        return;
      }
      const message =
        error instanceof ApiError
          ? error.status === 413
            ? `Server rejected the upload (413): the capture exceeds the server's configured maximum size. ${error.userMessage()}`
            : error.userMessage()
          : "Upload failed before completion.";
      setState({ ...initialState, kind: "error", message });
    } finally {
      abortRef.current = null;
    }
  };

  const pct = state.totalBytes > 0 ? Math.round((state.sentBytes / state.totalBytes) * 100) : 0;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="upload-heading"
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4"
    >
      <div ref={dialogRef} className="w-full max-w-lg rounded bg-surface-raised p-4 shadow">
        <div className="flex items-center justify-between">
          <h2 id="upload-heading" className="text-lg font-semibold">
            Upload Capture
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded border border-line px-2 py-1 text-sm"
          >
            Close
          </button>
        </div>

        <p className="mt-2 text-sm text-ink-muted">
          Only the first 16 bytes are inspected here for PCAP/PCAPNG magic and the configured size
          limit ({formatBytes(MAX_UPLOAD_BYTES)}, client-side mirror of the server default). The
          server re-validates magic bytes and computes the authoritative SHA-256 while streaming;
          extensions and MIME types are ignored.
        </p>

        <label
          className="mt-4 block rounded border border-dashed border-line p-4 text-sm"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            void onFileChosen(e.dataTransfer.files?.[0] ?? null);
          }}
        >
          Drop a .pcap / .pcapng file here, or choose a file:
          <input
            type="file"
            accept=".pcap,.pcapng"
            aria-label="Choose a capture file"
            className="mt-2 block w-full"
            onInput={(e) => void onFileInput(e)}
          />
        </label>

        {file !== null && (
          <dl className="mt-3 space-y-1 text-sm">
            <div className="flex gap-2">
              <dt className="font-medium">Selected:</dt>
              <dd>{file.name}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="font-medium">Size:</dt>
              <dd className="tnum">
                {formatBytes(file.size)} ({file.size.toLocaleString()} bytes)
              </dd>
            </div>
          </dl>
        )}

        {precheck !== null && (
          <p role="alert" className="mt-3 text-sm text-sev-critical">
            {precheck}
          </p>
        )}
        {oversized && (
          <p role="alert" className="mt-3 text-sm text-sev-critical">
            This file exceeds the configured maximum upload size ({formatBytes(MAX_UPLOAD_BYTES)}).
            The upload control is disabled; the server would reject it with 413 anyway.
          </p>
        )}

        {state.kind === "uploading" && (
          <div className="mt-4">
            <p className="text-sm" role="status">
              Uploading… <span className="tnum">{pct}%</span> ·{" "}
              <span className="tnum">
                {state.sentBytes.toLocaleString()} / {state.totalBytes.toLocaleString()} bytes
              </span>
            </p>
            <div
              role="progressbar"
              aria-valuenow={pct}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Upload progress"
              className="mt-1 h-2 overflow-hidden rounded bg-surface-sunken"
            >
              <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
            </div>
            <button
              type="button"
              onClick={() => abortRef.current?.abort()}
              className="mt-3 rounded border border-line px-2 py-1 text-sm"
            >
              Cancel upload
            </button>
          </div>
        )}

        {state.kind === "done" && state.serverSha256 !== null && (
          <div className="mt-4 rounded border border-line p-3 text-sm" role="status">
            <p className="font-medium">
              Upload complete — server-computed SHA-256 (authoritative):
            </p>
            <p className="mono break-all">{state.serverSha256}</p>
          </div>
        )}
        {state.message !== null && state.kind !== "done" && (
          <p role="alert" className="mt-3 text-sm">
            {state.message}
          </p>
        )}

        <div className="mt-4 flex gap-2">
          <button
            type="button"
            disabled={file === null || precheck !== null || oversized || state.kind === "uploading"}
            onClick={() => void startUpload()}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink disabled:opacity-50"
          >
            Start upload
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded border border-line px-3 py-1.5 text-sm"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
