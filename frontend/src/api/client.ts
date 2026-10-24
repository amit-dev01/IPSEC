import createClient from "openapi-fetch";

import type { components, paths } from "./schema";
import { getAccessToken, notifyUnauthorized } from "./token";

export type Schemas = components["schemas"];
export type CaptureResponse = Schemas["CaptureResponse"];
export type AnalysisResponse = Schemas["AnalysisResponse"];
export type AnalysisDetail = Schemas["AnalysisDetailResponse"];
export type EvidenceResponse = Schemas["EvidenceResponse"];
export type TokenResponse = Schemas["TokenResponse"];
export type MeResponse = Schemas["MeResponse"];

const DEFAULT_TIMEOUT_MS = 30_000;

/** Structured RFC 9457 / FastAPI error. `detail` is always safe display text. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly title: string;
  readonly detail: string;
  /** Field validation messages from a 422 `detail` array, keyed by field path. */
  readonly fields: Readonly<Record<string, string>>;
  readonly retryAfterSeconds: number | null;

  constructor(init: {
    status: number;
    code: string | null;
    title: string;
    detail: string;
    fields?: Readonly<Record<string, string>>;
    retryAfterSeconds?: number | null;
  }) {
    super(init.detail);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.title = init.title;
    this.detail = init.detail;
    this.fields = init.fields ?? {};
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
  }

  /** Safe, user-displayable summary (never a stack trace or local path). */
  userMessage(): string {
    if (this.status === 401) return "Your session has expired. Please sign in again.";
    if (this.status === 403) return "You do not have permission for this action.";
    if (this.status === 404) return "The requested record was not found.";
    if (this.status === 413) return "The file exceeds the server's maximum upload size.";
    if (this.status === 429) {
      return this.retryAfterSeconds !== null
        ? `Too many attempts. Retry after ${this.retryAfterSeconds} seconds.`
        : "Too many attempts. Please wait and retry.";
    }
    if (this.status === 422) return this.detail || "The submitted data was rejected (422).";
    if (this.status === 0) return "Network error — the backend could not be reached.";
    return this.detail || this.title || `Request failed (${this.status})`;
  }
}

interface ProblemBody {
  type?: unknown;
  title?: unknown;
  detail?: unknown;
  status?: unknown;
  code?: unknown;
}

export function parseProblem(body: unknown, status: number, retryAfter: string | null): ApiError {
  const fields: Record<string, string> = {};
  let detail = `Request failed (${status})`;
  let title = "Request failed";
  let code: string | null = null;

  if (body !== null && typeof body === "object") {
    const problem = body as ProblemBody;
    if (typeof problem.title === "string" && problem.title !== "") title = problem.title;
    if (typeof problem.code === "string" && problem.code !== "") code = problem.code;
    if (typeof problem.detail === "string" && problem.detail !== "") {
      detail = problem.detail;
      if (code === null) code = problem.detail;
    } else if (Array.isArray(problem.detail)) {
      // FastAPI validation errors: [{loc: [...], msg: "..."}]
      for (const item of problem.detail) {
        if (item !== null && typeof item === "object") {
          const entry = item as { loc?: unknown; msg?: unknown };
          const loc = Array.isArray(entry.loc) ? entry.loc.map(String).join(".") : "request";
          if (typeof entry.msg === "string") fields[loc] = entry.msg;
        }
      }
      if (Object.keys(fields).length > 0) detail = "Please correct the highlighted fields.";
    }
  }
  const retryAfterSeconds =
    retryAfter !== null && Number.isFinite(Number(retryAfter)) ? Number(retryAfter) : null;
  return new ApiError({ status, code, title, detail, fields, retryAfterSeconds });
}

async function readJsonBody(response: Response): Promise<unknown> {
  try {
    return (await response.clone().json()) as unknown;
  } catch {
    return null;
  }
}

function combinedSignal(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal !== undefined ? AbortSignal.any([signal, timeout]) : timeout;
}

// Same-origin: the browser (and jsdom in tests) supplies the origin; the
// dev proxy / production reverse proxy forwards /api/v1 to FastAPI.
const apiBaseUrl = typeof window !== "undefined" ? window.location.origin : "";
const baseClient = createClient<paths>({
  baseUrl: apiBaseUrl,
  // Delegate dynamically so the *current* global fetch is used (keeps MSW
  // interception in tests and any future fetch instrumentation intact).
  fetch: (input: Request) => globalThis.fetch(input),
});

baseClient.use({
  onRequest({ request }) {
    const token = getAccessToken();
    if (token !== null) request.headers.set("Authorization", `Bearer ${token}`);
    return request;
  },
  async onResponse({ response }) {
    if (response.ok) return response;
    const body = await readJsonBody(response);
    const error = parseProblem(body, response.status, response.headers.get("Retry-After"));
    if (response.status === 401) notifyUnauthorized();
    throw error;
  },
});

export interface RequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

function opts(options: RequestOptions): { signal: AbortSignal } {
  return { signal: combinedSignal(options.signal, options.timeoutMs ?? DEFAULT_TIMEOUT_MS) };
}

// ---- Typed endpoint helpers (types generated from the backend OpenAPI) ----

export async function login(
  email: string,
  password: string,
  options: RequestOptions = {},
): Promise<TokenResponse> {
  const { data, error } = await baseClient.POST("/api/v1/auth/login", {
    body: { email, password },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function fetchMe(options: RequestOptions = {}): Promise<MeResponse> {
  const { data, error } = await baseClient.GET("/api/v1/auth/me", opts(options));
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function listCaptures(
  params: { limit?: number; offset?: number; state?: string } = {},
  options: RequestOptions = {},
): Promise<Schemas["CapturePage"]> {
  const { data, error } = await baseClient.GET("/api/v1/captures", {
    params: { query: params },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function getCapture(
  captureId: string,
  options: RequestOptions = {},
): Promise<CaptureResponse> {
  const { data, error } = await baseClient.GET("/api/v1/captures/{capture_id}", {
    params: { path: { capture_id: captureId } },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function deleteCapture(
  captureId: string,
  options: RequestOptions = {},
): Promise<void> {
  const { error } = await baseClient.DELETE("/api/v1/captures/{capture_id}", {
    params: { path: { capture_id: captureId } },
    ...opts(options),
  });
  if (error !== undefined) throw error;
}

export async function createAnalysis(
  captureId: string,
  options: RequestOptions = {},
): Promise<AnalysisResponse> {
  const { data, error } = await baseClient.POST("/api/v1/captures/{capture_id}/analyses", {
    params: { path: { capture_id: captureId } },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function getAnalysis(
  analysisId: string,
  options: RequestOptions = {},
): Promise<Schemas["AnalysisDetailResponse"]> {
  const { data, error } = await baseClient.GET("/api/v1/analyses/{analysis_id}", {
    params: { path: { analysis_id: analysisId } },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function listCaptureAnalyses(
  captureId: string,
  params: { limit?: number; offset?: number; status?: string } = {},
  options: RequestOptions = {},
): Promise<Schemas["AnalysisPage"]> {
  const { data, error } = await baseClient.GET("/api/v1/captures/{capture_id}/analyses", {
    params: { path: { capture_id: captureId }, query: params },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function getManifest(
  captureId: string,
  options: RequestOptions = {},
): Promise<Schemas["ManifestResponse"]> {
  const { data, error } = await baseClient.GET("/api/v1/captures/{capture_id}/manifest", {
    params: { path: { capture_id: captureId } },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export async function attachManifest(
  captureId: string,
  manifest: Schemas["LabManifestV1"],
  options: RequestOptions = {},
): Promise<Schemas["ManifestResponse"]> {
  const { data, error } = await baseClient.POST("/api/v1/captures/{capture_id}/manifest", {
    params: { path: { capture_id: captureId } },
    body: manifest,
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

/** Backend readiness (unauthenticated). Resolves false on any failure. */
export async function fetchReadiness(): Promise<boolean> {
  try {
    const response = await fetch(`${apiBaseUrl}/api/v1/health/ready`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) return false;
    const body = (await response.json()) as { status?: unknown };
    return body.status === "ready";
  } catch {
    return false;
  }
}

export async function retryAnalysis(
  analysisId: string,
  options: RequestOptions = {},
): Promise<AnalysisResponse> {
  const { data, error } = await baseClient.POST("/api/v1/analyses/{analysis_id}/retry", {
    params: { path: { analysis_id: analysisId } },
    ...opts(options),
  });
  if (data === undefined)
    throw (
      error ??
      new ApiError({
        status: 0,
        code: null,
        title: "Network error",
        detail: "No response from server.",
      })
    );
  return data;
}

export function downloadCapture(captureId: string, options: RequestOptions = {}): Promise<void> {
  return downloadFile(`/api/v1/captures/${captureId}/download`, "capture.pcap", options);
}
export function downloadReport(
  analysisId: string,
  format: "json" | "pdf",
  options: RequestOptions = {},
): Promise<void> {
  return downloadFile(
    `/api/v1/analyses/${analysisId}/report?format=${format}`,
    `report.${format}`,
    options,
  );
}
/** Fetch a file as Blob via authenticated fetch (token never in URL). */
export async function fetchBlob(path: string, options: RequestOptions = {}): Promise<Blob> {
  const token = getAccessToken();
  const headers: Record<string, string> = {};
  if (token !== null) headers["Authorization"] = `Bearer ${token}`;
  const url = path.startsWith("http") ? path : `${apiBaseUrl}${path}`;
  const response = await fetch(url, {
    method: "GET",
    headers,
    signal: combinedSignal(options.signal, options.timeoutMs ?? 10 * 60_000),
  });
  if (!response.ok) {
    const body = await readJsonBody(response);
    const error = parseProblem(body, response.status, response.headers.get("Retry-After"));
    if (response.status === 401) notifyUnauthorized();
    throw error;
  }
  return response.blob();
}

/** Authenticated JSON GET for optional admin capabilities. Callers must
 * feature-detect: a 404 means the backend does not expose the capability. */
export async function fetchJson(path: string, options: RequestOptions = {}): Promise<unknown> {
  const blob = await fetchBlob(path, options);
  return JSON.parse(await blob.text()) as unknown;
}

export async function postJson(
  path: string,
  body: unknown,
  options: RequestOptions = {},
): Promise<unknown> {
  const token = getAccessToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token !== null) headers["Authorization"] = `Bearer ${token}`;
  const url = path.startsWith("http") ? path : `${apiBaseUrl}${path}`;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: combinedSignal(options.signal, options.timeoutMs ?? 60_000),
  });
  if (!response.ok) {
    const parsed = await readJsonBody(response);
    const error = parseProblem(parsed, response.status, response.headers.get("Retry-After"));
    if (response.status === 401) notifyUnauthorized();
    throw error;
  }
  return response.status === 204 ? null : ((await readJsonBody(response)) as unknown);
}

/** Authoritative structured report document (GET .../report?format=json). */
export async function fetchReportJson(
  analysisId: string,
  options: RequestOptions = {},
): Promise<Record<string, unknown>> {
  const blob = await fetchBlob(`/api/v1/analyses/${analysisId}/report?format=json`, options);
  return JSON.parse(await blob.text()) as Record<string, unknown>;
}

export function exportDataset(options: RequestOptions = {}): Promise<void> {
  return downloadFile("/api/v1/admin/exports/flow-dataset", "flow-dataset.json", options);
}

// ---- Multipart upload via XHR (fetch has no upload progress) ----

export interface UploadOptions extends RequestOptions {
  onProgress?: (loadedBytes: number, totalBytes: number | null) => void;
}

export function uploadCapture(file: File, options: UploadOptions = {}): Promise<CaptureResponse> {
  return new Promise<CaptureResponse>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/captures");
    const token = getAccessToken();
    if (token !== null) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.responseType = "text";
    xhr.timeout = options.timeoutMs ?? 10 * 60_000;

    xhr.upload.onprogress = (event) => {
      options.onProgress?.(event.loaded, event.lengthComputable ? event.total : null);
    };
    const onAbort = (): void => xhr.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    xhr.onabort = () => reject(new DOMException("Upload cancelled", "AbortError"));
    xhr.onerror = () =>
      reject(
        new ApiError({ status: 0, code: null, title: "Network error", detail: "Upload failed." }),
      );
    xhr.ontimeout = () =>
      reject(
        new ApiError({ status: 0, code: "timeout", title: "Timeout", detail: "Upload timed out." }),
      );
    xhr.onload = () => {
      options.signal?.removeEventListener("abort", onAbort);
      let body: unknown;
      try {
        body = JSON.parse(xhr.responseText) as unknown;
      } catch {
        body = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as CaptureResponse);
        return;
      }
      const error = parseProblem(body, xhr.status, xhr.getResponseHeader("Retry-After"));
      if (xhr.status === 401) notifyUnauthorized();
      reject(error);
    };

    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}

// ---- Authenticated Blob downloads (tokens never in URLs) ----

export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

function filenameFromDisposition(header: string | null, fallback: string): string {
  if (header === null) return fallback;
  const match = /filename="?([^";]+)"?/.exec(header);
  const raw = match?.[1];
  if (raw === undefined) return fallback;
  const clean = raw.replace(/[\\/:*?"<>|]/g, "_").slice(0, 120);
  return clean === "" ? fallback : clean;
}

export async function downloadFile(
  path: string,
  fallbackFilename: string,
  options: RequestOptions = {},
): Promise<void> {
  const token = getAccessToken();
  const headers: Record<string, string> = {};
  if (token !== null) headers["Authorization"] = `Bearer ${token}`;
  const url = path.startsWith("http") ? path : `${apiBaseUrl}${path}`;
  const response = await fetch(url, {
    method: "GET",
    headers,
    signal: combinedSignal(options.signal, options.timeoutMs ?? 10 * 60_000),
  });
  if (!response.ok) {
    const body = await readJsonBody(response);
    const error = parseProblem(body, response.status, response.headers.get("Retry-After"));
    if (response.status === 401) notifyUnauthorized();
    throw error;
  }
  const blob = await response.blob();
  saveBlob(
    blob,
    filenameFromDisposition(response.headers.get("Content-Disposition"), fallbackFilename),
  );
}
