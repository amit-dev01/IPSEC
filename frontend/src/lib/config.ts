/**
 * Client-side upload pre-check limit. Mirrors the backend default
 * (max_upload_bytes = 512 MiB); the SERVER limit is authoritative and a
 * 413 is always handled. Override at build time with VITE_MAX_UPLOAD_BYTES.
 */
const parsed = Number(import.meta.env.VITE_MAX_UPLOAD_BYTES);
export const MAX_UPLOAD_BYTES = Number.isFinite(parsed) && parsed > 0 ? parsed : 512 * 1024 * 1024;
