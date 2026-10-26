import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";

import { ApiError, fetchJson } from "@/api/client";
import { Skeleton, EmptyState } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";

interface AuditEvent {
  id?: string;
  timestamp?: string;
  created_at?: string;
  actor?: string;
  actor_user_id?: string | null;
  action?: string;
  resource_type?: string;
  resource_id?: string | null;
  event_hash?: string;
  previous_hash?: string | null;
  hash?: string;
}

const PAGE_SIZE = 20;

/**
 * Tamper-evident audit trail viewer. The backend records audit events
 * server-side; this screen consumes the admin audit API when the backend
 * exposes it and renders an explicit unavailable state otherwise — it never
 * fabricates events. The hash chain is tamper-evident (a later edit breaks
 * verification); it is NOT a public blockchain or hardware ledger.
 */
export default function AuditPage(): ReactNode {
  const { organizationId } = useAuth();
  const [page, setPage] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const [resourceFilter, setResourceFilter] = useState("");

  const query = useQuery({
    queryKey: ["org", organizationId, "admin", "audit", { page, actionFilter, resourceFilter }],
    queryFn: async ({ signal }) => {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(page * PAGE_SIZE),
      });
      if (actionFilter !== "") params.set("action", actionFilter);
      if (resourceFilter !== "") params.set("resource_type", resourceFilter);
      const data = (await fetchJson(`/api/v1/admin/audit-events?${params.toString()}`, {
        signal,
      })) as { items?: AuditEvent[]; total?: number };
      return { items: data.items ?? [], total: data.total ?? 0 };
    },
    enabled: organizationId !== null,
    retry: false,
  });

  const unavailable =
    query.isError && query.error instanceof ApiError && query.error.status === 404;

  return (
    <section aria-labelledby="audit-heading" className="space-y-6">
      <div>
        <h1
          id="audit-heading"
          className="font-display text-2xl font-semibold tracking-tight text-[#1d1d1f]"
        >
          Tamper-Evident Audit Trail
        </h1>
        <p className="mt-1 max-w-3xl text-xs text-[#707070]">
          Events are hash-chained (each event references the previous event&apos;s hash), making
          later tampering detectable on verification. This is a{" "}
          <strong>tamper-evident audit log</strong> — not a public blockchain and not an immutable
          hardware ledger.
        </p>
      </div>

      {unavailable ? (
        <div className="mt-4">
          <EmptyState title="Audit API not exposed by this backend">
            <p>
              The running backend records audit events internally but does not expose an audit query
              endpoint in its OpenAPI contract. No events are fabricated here; expose the admin
              audit endpoint to enable this viewer.
            </p>
          </EmptyState>
        </div>
      ) : (
        <>
          <div className="apple-card p-4">
            <fieldset className="flex flex-wrap items-center gap-4 text-xs">
              <legend className="sr-only">Filter audit events</legend>
              <label className="flex items-center gap-2">
                <span className="font-medium text-[#707070]">Action</span>
                <input
                  value={actionFilter}
                  onChange={(e) => {
                    setActionFilter(e.target.value);
                    setPage(0);
                  }}
                  placeholder="e.g. capture.uploaded"
                  className="rounded-full border border-[#d6d6d6] bg-white px-3.5 py-1.5 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3] focus:ring-1 focus:ring-[#0071e3]"
                />
              </label>
              <label className="flex items-center gap-2">
                <span className="font-medium text-[#707070]">Resource type</span>
                <input
                  value={resourceFilter}
                  onChange={(e) => {
                    setResourceFilter(e.target.value);
                    setPage(0);
                  }}
                  placeholder="e.g. capture"
                  className="rounded-full border border-[#d6d6d6] bg-white px-3.5 py-1.5 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3] focus:ring-1 focus:ring-[#0071e3]"
                />
              </label>
            </fieldset>
          </div>

          {query.isPending && <Skeleton label="Loading audit events" rows={5} />}
          {query.isError && !unavailable && (
            <p role="alert" className="text-xs text-[#d70015]">
              Could not load audit events.{" "}
              {query.error instanceof ApiError ? query.error.userMessage() : ""}
            </p>
          )}
          {query.isSuccess && query.data.items.length === 0 && (
            <div className="apple-card p-12 text-center text-xs text-[#707070]">
              No audit events match the specified filter criteria.
            </div>
          )}
          {query.isSuccess && query.data.items.length > 0 && (
            <div className="apple-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#e6e6e8] bg-[#fafafc] text-[#707070]">
                      <th scope="col" className="px-4 py-3 font-medium">
                        Timestamp (UTC)
                      </th>
                      <th scope="col" className="px-4 py-3 font-medium">
                        Actor
                      </th>
                      <th scope="col" className="px-4 py-3 font-medium">
                        Action
                      </th>
                      <th scope="col" className="px-4 py-3 font-medium">
                        Resource
                      </th>
                      <th scope="col" className="px-4 py-3 font-medium">
                        Event Hash Chain
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#e6e6e8] bg-white">
                    {query.data.items.map((event, i) => (
                      <tr key={event.id ?? i} className="hover:bg-[#fafafc]">
                        <td className="px-4 py-3 font-mono text-[#707070]">
                          {event.timestamp ?? event.created_at ?? "—"}
                        </td>
                        <td className="px-4 py-3 font-medium text-[#1d1d1f]">
                          {event.actor ?? event.actor_user_id ?? "system"}
                        </td>
                        <td className="px-4 py-3 font-mono text-[#0066cc]">
                          {event.action ?? "—"}
                        </td>
                        <td className="px-4 py-3 font-mono text-[#1d1d1f]">
                          {event.resource_type ?? "—"}/{event.resource_id ?? "—"}
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-[#707070]">
                          <span className="text-[#1d1d1f]">
                            {(event.event_hash ?? event.hash ?? "not reported").slice(0, 12)}…
                          </span>{" "}
                          ←{" "}
                          <span className="text-[#86868b]">
                            {event.previous_hash
                              ? `${event.previous_hash.slice(0, 12)}…`
                              : "genesis"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between border-t border-[#e6e6e8] bg-[#fafafc] px-4 py-3 text-xs">
                <span className="text-[#707070]">
                  Page {page + 1} · {query.data?.total ?? 0} events
                </span>
                <nav aria-label="Audit pages" className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={page === 0}
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    className="apple-btn-secondary text-xs disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <button
                    type="button"
                    disabled={(query.data?.total ?? 0) <= (page + 1) * PAGE_SIZE}
                    onClick={() => setPage((p) => p + 1)}
                    className="apple-btn-secondary text-xs disabled:opacity-40"
                  >
                    Next
                  </button>
                </nav>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}
