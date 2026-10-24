import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "@/api/client";

/** Client-error statuses that must never be auto-retried. */
export const NON_RETRYABLE_STATUSES: ReadonlySet<number> = new Set([400, 401, 403, 404, 413, 422]);

export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && NON_RETRYABLE_STATUSES.has(error.status)) return false;
  return failureCount < 2;
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        staleTime: 30_000,
        refetchOnWindowFocus: true,
      },
      mutations: { retry: false },
    },
  });
}
