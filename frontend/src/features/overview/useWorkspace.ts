import { useQueries, useQuery } from "@tanstack/react-query";

import { getAnalysis, listCaptureAnalyses, listCaptures } from "@/api/client";
import type { AnalysisResponse, CaptureResponse } from "@/api/client";

export interface WorkspaceData {
  captures: CaptureResponse[];
  capturesTotal: number;
  /** Flattened runs across the tenant's captures (composed per-capture). */
  runs: AnalysisResponse[];
  activeRuns: AnalysisResponse[];
  recentRuns: AnalysisResponse[];
  /** succeeded runs assessed only partially or with insufficient evidence */
  partialOrInsufficientCount: number;
  /** findings of severity high/critical across the most recent succeeded runs */
  recentHighRiskFindings: number;
  isPending: boolean;
  isError: boolean;
}

const CAPTURE_WINDOW = 50;
const RUNS_PER_CAPTURE = 20;
const DETAIL_WINDOW = 5;

/**
 * Workspace composition from the documented endpoints only. There is no
 * global analyses endpoint: runs are composed via GET /captures/{id}/analyses.
 * Assessment completeness is inferred from documented score nullability:
 * security null + risk set => partial; both null (succeeded) => insufficient.
 */
export function useWorkspace(organizationId: string | null): WorkspaceData {
  const capturesQuery = useQuery({
    queryKey: ["org", organizationId, "captures", { limit: CAPTURE_WINDOW, offset: 0 }],
    queryFn: ({ signal }) => listCaptures({ limit: CAPTURE_WINDOW, offset: 0 }, { signal }),
    enabled: organizationId !== null,
  });
  const captures = capturesQuery.data?.items ?? [];

  const runQueries = useQueries({
    queries: captures.map((capture) => ({
      queryKey: [
        "org",
        organizationId,
        "captures",
        capture.id,
        "analyses",
        { limit: RUNS_PER_CAPTURE },
      ],
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        listCaptureAnalyses(capture.id, { limit: RUNS_PER_CAPTURE }, { signal }),
      enabled: organizationId !== null,
    })),
  });

  const runs = runQueries
    .flatMap((q) => q.data?.items ?? [])
    .sort((a, b) => (a.queued_at < b.queued_at ? 1 : -1));
  const activeRuns = runs.filter((r) => r.status === "queued" || r.status === "running");
  const recentRuns = runs.slice(0, 10);
  const succeeded = runs.filter((r) => r.status === "succeeded");
  const partialOrInsufficientCount = succeeded.filter((r) => r.security_score === null).length;

  const detailQueries = useQueries({
    queries: succeeded.slice(0, DETAIL_WINDOW).map((run) => ({
      queryKey: ["org", organizationId, "analyses", run.id, "detail"],
      queryFn: ({ signal }: { signal: AbortSignal }) => getAnalysis(run.id, { signal }),
      enabled: organizationId !== null,
    })),
  });
  const recentHighRiskFindings = detailQueries
    .flatMap((q) => q.data?.findings ?? [])
    .filter((f) => f.severity === "high" || f.severity === "critical").length;

  return {
    captures,
    capturesTotal: capturesQuery.data?.total ?? 0,
    runs,
    activeRuns,
    recentRuns,
    partialOrInsufficientCount,
    recentHighRiskFindings,
    isPending: capturesQuery.isPending || runQueries.some((q) => q.isPending),
    isError: capturesQuery.isError,
  };
}
