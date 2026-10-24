import { useMutation, useQuery } from "@tanstack/react-query";
import type { FormEvent, ReactNode } from "react";
import { useState } from "react";
import { Link } from "react-router";

import { ApiError, fetchJson, postJson } from "@/api/client";
import { EmptyState, Skeleton } from "@/components/ui";
import { useAuth } from "@/features/auth/auth-context";

interface Allowlist {
  agents: { id: string; label?: string }[];
  interfaces: { id: string; label?: string }[];
  profiles: { id: string; label?: string; max_duration_seconds?: number; max_bytes?: number }[];
  duration_options_seconds: number[];
  max_bytes_options: number[];
}

interface TriggerResult {
  capture_id?: string;
  analysis_id?: string;
  status?: string;
}

const FALLBACK_DURATIONS = [30, 60, 120, 300];
const FALLBACK_BYTES = [10_000_000, 50_000_000, 100_000_000, 524_288_000];

/**
 * Optional passive capture agent trigger. Strictly bounded: ONLY
 * administrator-allowlisted dropdowns fetched from the API. There are NO
 * free-text inputs for interface names, shell flags, paths, or filters.
 * When the backend does not expose the agent capability, a clean disabled
 * status card is shown instead.
 */
export default function LiveCapturePage(): ReactNode {
  const { organizationId } = useAuth();
  const [agentId, setAgentId] = useState("");
  const [interfaceId, setInterfaceId] = useState("");
  const [profileId, setProfileId] = useState("");
  const [duration, setDuration] = useState("");
  const [maxBytes, setMaxBytes] = useState("");
  const [result, setResult] = useState<TriggerResult | null>(null);

  const allowlistQuery = useQuery({
    queryKey: ["org", organizationId, "admin", "live-capture", "allowlist"],
    queryFn: async ({ signal }) =>
      (await fetchJson("/api/v1/admin/live-capture/allowlist", { signal })) as Allowlist,
    enabled: organizationId !== null,
    retry: false,
  });

  const disabled =
    allowlistQuery.isError &&
    allowlistQuery.error instanceof ApiError &&
    (allowlistQuery.error.status === 404 || allowlistQuery.error.status === 403);

  const triggerMutation = useMutation({
    mutationFn: async () =>
      (await postJson("/api/v1/admin/live-capture/trigger", {
        agent_id: agentId,
        interface_id: interfaceId,
        capture_profile: profileId,
        duration_seconds: Number(duration),
        max_bytes: Number(maxBytes),
      })) as TriggerResult,
    onSuccess: (data) => setResult(data),
  });

  if (allowlistQuery.isPending)
    return <Skeleton label="Checking live capture availability" rows={3} />;

  if (disabled) {
    return (
      <section aria-labelledby="live-heading">
        <h1 id="live-heading" className="text-xl font-semibold">
          Passive Capture Agent
        </h1>
        <div className="mt-4">
          <EmptyState title="Passive Live Capture Disabled by Administrator Policy">
            <p>
              The optional passive capture agent is not enabled on this backend (or not exposed to
              this deployment). Offline PCAP upload remains available in the Capture Vault.
            </p>
          </EmptyState>
        </div>
      </section>
    );
  }

  if (allowlistQuery.isError || allowlistQuery.data === undefined) {
    return (
      <p role="alert" className="text-sm text-sev-critical">
        Could not load the agent allowlist.{" "}
        {allowlistQuery.error instanceof ApiError ? allowlistQuery.error.userMessage() : ""}
      </p>
    );
  }

  const allow = allowlistQuery.data;
  const durations = allow.duration_options_seconds?.length
    ? allow.duration_options_seconds
    : FALLBACK_DURATIONS;
  const byteOptions = allow.max_bytes_options?.length ? allow.max_bytes_options : FALLBACK_BYTES;

  const onSubmit = (event: FormEvent): void => {
    event.preventDefault();
    triggerMutation.mutate();
  };

  return (
    <section aria-labelledby="live-heading">
      <h1 id="live-heading" className="text-xl font-semibold">
        Passive Capture Agent (bounded, allowlisted)
      </h1>
      <p className="mt-1 max-w-3xl text-sm text-ink-muted">
        Every parameter below comes from administrator-allowlisted values returned by the API. This
        console intentionally has <strong>no free-text fields</strong> for interface names, shell
        flags, file paths, or capture filters — the backend and agent validate the allowlisted tuple
        again server-side.
      </p>

      <form onSubmit={onSubmit} className="mt-4 grid max-w-xl gap-3 text-sm">
        <label>
          Agent
          <select
            required
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            className="w-full rounded border border-line px-2 py-1"
          >
            <option value="">Select an allowlisted agent…</option>
            {allow.agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label ?? a.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          Interface (allowlisted)
          <select
            required
            value={interfaceId}
            onChange={(e) => setInterfaceId(e.target.value)}
            className="w-full rounded border border-line px-2 py-1"
          >
            <option value="">Select an allowlisted interface…</option>
            {allow.interfaces.map((i) => (
              <option key={i.id} value={i.id}>
                {i.label ?? i.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          Approved capture profile
          <select
            required
            value={profileId}
            onChange={(e) => setProfileId(e.target.value)}
            className="w-full rounded border border-line px-2 py-1"
          >
            <option value="">Select an approved profile…</option>
            {allow.profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label ?? p.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          Bounded duration (seconds)
          <select
            required
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            className="w-full rounded border border-line px-2 py-1"
          >
            <option value="">Select duration…</option>
            {durations.map((d) => (
              <option key={d} value={d}>
                {d}s
              </option>
            ))}
          </select>
        </label>
        <label>
          Bounded max bytes
          <select
            required
            value={maxBytes}
            onChange={(e) => setMaxBytes(e.target.value)}
            className="w-full rounded border border-line px-2 py-1"
          >
            <option value="">Select byte budget…</option>
            {byteOptions.map((b) => (
              <option key={b} value={b}>
                {b.toLocaleString()} bytes
              </option>
            ))}
          </select>
        </label>
        <button
          type="submit"
          disabled={triggerMutation.isPending}
          className="rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-50"
        >
          Start bounded passive capture
        </button>
        {triggerMutation.isError && (
          <p role="alert" className="text-sev-critical">
            {triggerMutation.error instanceof ApiError
              ? triggerMutation.error.userMessage()
              : "Trigger failed."}
          </p>
        )}
      </form>

      {result !== null && (
        <div role="status" className="mt-4 rounded border border-line p-3 text-sm">
          <p>
            Capture accepted{result.status ? ` (${result.status})` : ""}. It ingests through the
            standard backend pipeline (magic validation, SHA-256, tenant scoping).
          </p>
          {result.capture_id !== undefined && (
            <p className="mt-1">
              Resulting capture:{" "}
              <Link to={`/captures/${result.capture_id}`} className="mono underline">
                {result.capture_id}
              </Link>
            </p>
          )}
          {result.analysis_id !== undefined && (
            <p>
              Queued analysis:{" "}
              <Link to={`/analyses/${result.analysis_id}`} className="mono underline">
                {result.analysis_id}
              </Link>
            </p>
          )}
        </div>
      )}
    </section>
  );
}
