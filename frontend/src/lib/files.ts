/**
 * Magic-byte pre-validation ONLY. Reads at most the first 16 bytes via
 * Blob.slice; never parses the capture and never loads it into memory.
 * Backend magic-byte validation and SHA-256 are authoritative.
 */
export type CaptureKind = "pcap" | "pcapng" | "unknown";

export async function sniffCaptureKind(file: Blob): Promise<CaptureKind> {
  const head = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  const b = (i: number): number => head[i] ?? -1;
  // PCAPNG section header block type: 0x0A0D0D0A
  if (b(0) === 0x0a && b(1) === 0x0d && b(2) === 0x0d && b(3) === 0x0a) return "pcapng";
  // Classic PCAP magic, either byte order, microsecond (D4 C3 B2 A1 /
  // A1 B2 C3 D4) and nanosecond (4D 3C B2 A1 / A1 B2 3C 4D) variants.
  if (
    (b(0) === 0xd4 && b(1) === 0xc3 && b(2) === 0xb2 && b(3) === 0xa1) ||
    (b(0) === 0xa1 && b(1) === 0xb2 && b(2) === 0xc3 && b(3) === 0xd4) ||
    (b(0) === 0x4d && b(1) === 0x3c && b(2) === 0xb2 && b(3) === 0xa1) ||
    (b(0) === 0xa1 && b(1) === 0xb2 && b(2) === 0x3c && b(3) === 0x4d)
  ) {
    return "pcap";
  }
  return "unknown";
}

/** Null when the first bytes are neither PCAP nor PCAPNG magic. */
export async function detectCaptureKind(file: Blob): Promise<CaptureKind | null> {
  const kind = await sniffCaptureKind(file);
  return kind === "unknown" ? null : kind;
}
