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
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-md p-4"
    >
      <div ref={dialogRef} className="apple-card w-full max-w-lg p-8 shadow-2xl">
        <div className="flex items-center justify-between">
          <h2
            id="upload-heading"
            className="font-display text-2xl font-semibold tracking-tight text-[#1d1d1f]"
          >
            Upload Capture
          </h2>
          <button type="button" onClick={onClose} className="apple-btn-secondary px-3 py-1 text-xs">
            Close
          </button>
        </div>

        <p className="mt-2 text-xs leading-relaxed text-[#707070]">
          Only the first 16 bytes are inspected client-side for PCAP/PCAPNG magic and the configured
          size limit ({formatBytes(MAX_UPLOAD_BYTES)}). The server re-validates magic bytes and
          computes the authoritative SHA-256 while streaming.
        </p>

        <label
          className="mt-5 block cursor-pointer rounded-2xl border-2 border-dashed border-[#d6d6d6] bg-[#fafafc] p-6 text-center text-xs text-[#707070] transition hover:border-[#0071e3] hover:bg-[#ffffff]"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            void onFileChosen(e.dataTransfer.files?.[0] ?? null);
          }}
        >
          <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-[#f5f5f7] text-[#0071e3] mb-2 font-bold text-lg">
            ↑
          </div>
          <span className="font-semibold text-[#1d1d1f] block text-sm">
            Drop a .pcap / .pcapng file here
          </span>
          <span className="mt-1 block text-xs">or click to browse from device</span>
          <input
            type="file"
            accept=".pcap,.pcapng"
            aria-label="Choose a capture file"
            className="mt-3 block w-full text-xs text-[#707070] file:mr-3 file:rounded-full file:border-0 file:bg-[#0071e3] file:px-3 file:py-1 file:text-xs file:font-semibold file:text-white hover:file:bg-[#0077ed]"
            onInput={(e) => void onFileInput(e)}
          />
        </label>

        {file !== null && (
          <dl className="mt-4 space-y-1 rounded-xl bg-[#f5f5f7] p-3 text-xs text-[#1d1d1f]">
            <div className="flex justify-between">
              <dt className="font-semibold text-[#707070]">Selected:</dt>
              <dd className="font-medium truncate max-w-[280px]">{file.name}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="font-semibold text-[#707070]">Size:</dt>
              <dd className="tnum font-medium">
                {formatBytes(file.size)} ({file.size.toLocaleString()} bytes)
              </dd>
            </div>
          </dl>
        )}

        {precheck !== null && (
          <p role="alert" className="mt-3 text-xs font-medium text-[#d70015]">
            {precheck}
          </p>
        )}
        {oversized && (
          <p role="alert" className="mt-3 text-xs font-medium text-[#d70015]">
            This file exceeds the configured maximum upload size ({formatBytes(MAX_UPLOAD_BYTES)}).
            The upload control is disabled; the server would reject it with 413 anyway.
          </p>
        )}

        {state.kind === "uploading" && (
          <div className="mt-4 space-y-2">
            <p className="text-xs font-medium text-[#1d1d1f]" role="status">
              Uploading… <span className="tnum font-bold text-[#0071e3]">{pct}%</span> ·{" "}
              <span className="tnum text-[#707070]">
                {state.sentBytes.toLocaleString()} / {state.totalBytes.toLocaleString()} bytes
              </span>
            </p>
            <div
              role="progressbar"
              aria-valuenow={pct}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Upload progress"
              className="h-2 w-full overflow-hidden rounded-full bg-[#e6e6e8]"
            >
              <div
                className="h-full rounded-full bg-[#0071e3] transition-all duration-200"
                style={{ width: `${pct}%` }}
              />
            </div>
            <button
              type="button"
              onClick={() => abortRef.current?.abort()}
              className="apple-btn-secondary mt-2 px-3 py-1 text-xs"
            >
              Cancel upload
            </button>
          </div>
        )}

        {state.kind === "done" && state.serverSha256 !== null && (
          <div
            className="mt-4 rounded-xl border border-[#0071e3]/30 bg-[#0071e3]/5 p-3 text-xs text-[#1d1d1f]"
            role="status"
          >
            <p className="font-semibold text-[#0071e3]">
              Upload complete — server-computed SHA-256 (authoritative):
            </p>
            <p className="mono mt-1 break-all font-semibold">{state.serverSha256}</p>
          </div>
        )}
        {state.message !== null && state.kind !== "done" && (
          <p role="alert" className="mt-3 text-xs text-[#707070]">
            {state.message}
          </p>
        )}

        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            disabled={file === null || precheck !== null || oversized || state.kind === "uploading"}
            onClick={() => void startUpload()}
            className="apple-btn-primary disabled:opacity-40"
          >
            Start upload
          </button>
          <button type="button" onClick={onClose} className="apple-btn-secondary">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
