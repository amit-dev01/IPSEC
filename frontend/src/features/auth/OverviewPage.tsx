import type { ReactNode } from "react";

import { useAuth } from "@/features/auth/auth-context";

const CAPABILITY_LABELS: Record<string, string> = {
  admin: "Full access: captures, analyses, reports, audit review, dataset export, agent controls.",
  analyst: "Captures upload/delete, manifest editing, run/retry analyses, reports.",
  viewer: "Read-only: captures, analyses, and reports.",
};

export default function OverviewPage(): ReactNode {
  const { email, organizationId, role } = useAuth();
  return (
    <section aria-labelledby="overview-heading">
      <h1 id="overview-heading" className="text-xl font-semibold">
        Session overview
      </h1>
      <dl className="mt-4 space-y-2 text-sm">
        <div>
          <dt className="font-medium">Signed in as</dt>
          <dd>{email}</dd>
        </div>
        <div>
          <dt className="font-medium">Organization (tenant)</dt>
          <dd className="mono">{organizationId}</dd>
        </div>
        <div>
          <dt className="font-medium">Role</dt>
          <dd>
            {role} — {role !== null ? CAPABILITY_LABELS[role] : ""}
          </dd>
        </div>
      </dl>
      <p className="mt-6 max-w-prose text-sm text-ink-muted">
        Use <strong>Captures</strong> to work with uploaded PCAP/PCAPNG files. Unknown or
        unobservable protocol properties are always shown as unknown — never as secure.
      </p>
    </section>
  );
}
