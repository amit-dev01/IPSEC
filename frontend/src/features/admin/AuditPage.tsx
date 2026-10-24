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
    <section aria-labelledby="audit-heading">
      <h1 id="audit-heading" className="text-xl font-semibold">
        Tamper-Evident Audit Trail
      </h1>
      <p className="mt-1 max-w-3xl text-sm text-ink-muted">
        Events are hash-chained (each event references the previous event&apos;s hash), making later
        tampering detectable on verification. This is a <strong>tamper-evident audit log</strong> —
        not a public blockchain and not an immutable hardware ledger.
      </p>

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
          <fieldset className="mt-4 flex flex-wrap gap-3 text-sm">
            <legend className="sr-only">Filter audit events</legend>
            <label>
              Action{" "}
              <input
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setPage(0);
                }}
                placeholder="e.g. capture.uploaded"
                className="rounded border border-line px-2 py-1"
              />
            </label>
            <label>
              Resource type{" "}
              <input
                value={resourceFilter}
                onChange={(e) => {
                  setResourceFilter(e.target.value);
                  setPage(0);
                }}
                placeholder="e.g. capture"
                className="rounded border border-line px-2 py-1"
              />
            </label>
          </fieldset>

          {query.isPending && <Skeleton label="Loading audit events" rows={5} />}
          {query.isError && !unavailable && (
            <p role="alert" className="mt-3 text-sm text-sev-critical">
              Could not load audit events.{" "}
              {query.error instanceof ApiError ? query.error.userMessage() : ""}
            </p>
          )}
          {query.isSuccess && query.data.items.length === 0 && (
            <p className="mt-3 text-sm text-ink-muted">No audit events match.</p>
          )}
          {query.isSuccess && query.data.items.length > 0 && (
            <table className="mt-3 w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-line text-left">
                  <th scope="col" className="py-2 pr-3">
                    Timestamp (UTC)
                  </th>
                  <th scope="col" className="py-2 pr-3">
                    Actor
                  </th>
                  <th scope="col" className="py-2 pr-3">
                    Action
                  </th>
                  <th scope="col" className="py-2 pr-3">
                    Resource
                  </th>
                  <th scope="col" className="py-2">
                    Event hash ← previous
                  </th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((event, i) => (
                  <tr key={event.id ?? i} className="border-b border-line align-top">
                    <td className="tnum py-2 pr-3">{event.timestamp ?? event.created_at ?? "—"}</td>
                    <td className="py-2 pr-3">{event.actor ?? event.actor_user_id ?? "system"}</td>
                    <td className="mono py-2 pr-3 text-xs">{event.action ?? "—"}</td>
                    <td className="mono py-2 pr-3 text-xs">
                      {event.resource_type ?? "—"}/{event.resource_id ?? "—"}
                    </td>
                    <td className="mono py-2 text-xs">
                      {(event.event_hash ?? event.hash ?? "not reported").slice(0, 12)}… ←{" "}
                      {event.previous_hash ? `${event.previous_hash.slice(0, 12)}…` : "genesis"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <nav aria-label="Audit pages" className="mt-3 flex items-center gap-3 text-sm">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="rounded border border-line px-2 py-1 disabled:opacity-50"
            >
              Previous
            </button>
            <span className="tnum">
              Page {page + 1} · {query.data?.total ?? 0} events
            </span>
            <button
              type="button"
              disabled={(query.data?.total ?? 0) <= (page + 1) * PAGE_SIZE}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-line px-2 py-1 disabled:opacity-50"
            >
              Next
            </button>
          </nav>
        </>
      )}
    </section>
  );
}
