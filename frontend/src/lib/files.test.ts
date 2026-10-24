import { describe, expect, it } from "vitest";

import { detectCaptureKind, sniffCaptureKind } from "./files";

function fileWithHead(bytes: number[]): File {
  return new File([new Uint8Array([...bytes, ...new Array(64).fill(0)])], "x.bin");
}

describe("magic-byte pre-validation (first 16 bytes only)", () => {
  it("accepts PCAP microsecond magics both byte orders", async () => {
    await expect(detectCaptureKind(fileWithHead([0xd4, 0xc3, 0xb2, 0xa1]))).resolves.toBe("pcap");
    await expect(detectCaptureKind(fileWithHead([0xa1, 0xb2, 0xc3, 0xd4]))).resolves.toBe("pcap");
  });

  it("accepts PCAP nanosecond magics both byte orders", async () => {
    await expect(detectCaptureKind(fileWithHead([0x4d, 0x3c, 0xb2, 0xa1]))).resolves.toBe("pcap");
    await expect(detectCaptureKind(fileWithHead([0xa1, 0xb2, 0x3c, 0x4d]))).resolves.toBe("pcap");
  });

  it("accepts PCAPNG section header", async () => {
    await expect(detectCaptureKind(fileWithHead([0x0a, 0x0d, 0x0d, 0x0a]))).resolves.toBe("pcapng");
  });

  it("rejects non-capture bytes before any upload", async () => {
    await expect(detectCaptureKind(fileWithHead([0x25, 0x50, 0x44, 0x46]))).resolves.toBeNull();
    await expect(sniffCaptureKind(fileWithHead([0x00, 0x01]))).resolves.toBe("unknown");
  });
});
