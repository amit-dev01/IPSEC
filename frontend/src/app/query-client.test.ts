import { describe, expect, it, vi } from "vitest";

import { ApiError } from "@/api/client";
import { shouldRetry } from "@/app/query-client";

describe("query retry policy", () => {
  it.each([400, 401, 403, 404, 413, 422])("never auto-retries status %i", (status) => {
    const error = new ApiError({
      status,
      code: "x",
      title: "x",
      detail: "x",
    });
    expect(shouldRetry(0, error)).toBe(false);
    expect(shouldRetry(1, error)).toBe(false);
  });

  it("retries transient failures at most twice", () => {
    const error = new ApiError({ status: 503, code: "x", title: "x", detail: "x" });
    expect(shouldRetry(0, error)).toBe(true);
    expect(shouldRetry(1, error)).toBe(true);
    expect(shouldRetry(2, error)).toBe(false);
    expect(shouldRetry(0, new Error("network"))).toBe(true);
  });

  it("fetchQuery with a 422 fetcher calls it exactly once", async () => {
    const { createQueryClient } = await import("@/app/query-client");
    const client = createQueryClient();
    const fetcher = vi.fn(() =>
      Promise.reject(new ApiError({ status: 422, code: "x", title: "x", detail: "x" })),
    );
    await expect(
      client.fetchQuery({ queryKey: ["test-422"], queryFn: fetcher, retry: shouldRetry }),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
