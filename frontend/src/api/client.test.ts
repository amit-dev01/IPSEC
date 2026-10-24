import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  downloadFile,
  getCapture,
  listCaptures,
  login,
  parseProblem,
} from "@/api/client";
import { clearAccessToken, setAccessToken, setUnauthorizedHandler } from "@/api/token";

afterEach(() => {
  clearAccessToken();
  setUnauthorizedHandler(null);
  vi.restoreAllMocks();
});

describe("typed client", () => {
  it("performs a typed GET and returns the generated-schema shape", async () => {
    const page = await listCaptures({ limit: 50, offset: 0 });
    expect(page.items).toEqual([]);
    expect(page.total).toBe(0);
  });

  it("performs a typed POST login and returns a token response", async () => {
    const token = await login("analyst@example.test", "correct-password");
    expect(token.token_type).toBe("bearer");
    expect(token.access_token).toContain("test-token-");
  });

  it("parses Problem Details into a structured ApiError", async () => {
    const error = await getCapture("missing").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(404);
    expect(apiError.code).toBe("capture_not_found");
    expect(apiError.detail).toBe("capture_not_found");
  });

  it("parses 422 validation detail arrays into field errors", () => {
    const error = parseProblem(
      { detail: [{ loc: ["body", "email"], msg: "field required" }] },
      422,
      null,
    );
    expect(error.fields["body.email"]).toBe("field required");
  });

  it("triggers the unauthorized handler and clears the token on 401", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setAccessToken("test-token-expired");
    // Replace the stored token with an invalid one: /auth/me will 401.
    setAccessToken("not-a-real-token");
    const { fetchMe } = await import("@/api/client");
    await expect(fetchMe()).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
    const { getAccessToken } = await import("@/api/token");
    expect(getAccessToken()).toBeNull();
  });

  it("downloads via authenticated Blob and revokes the object URL", async () => {
    setAccessToken("test-token-analyst");
    const created: string[] = [];
    const revoked: string[] = [];
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => {
      const url = `blob:mock-${created.length}`;
      created.push(url);
      return url;
    });
    vi.spyOn(URL, "revokeObjectURL").mockImplementation((url) => {
      revoked.push(url);
    });
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => undefined);
    await downloadFile("/api/v1/captures/abc/download", "fallback.pcap");
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(created).toHaveLength(1);
    expect(revoked).toEqual(created);
  });
});
