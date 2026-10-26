import type { ReactNode } from "react";
import { Component } from "react";

export function Skeleton({ label, rows = 3 }: { label: string; rows?: number }): ReactNode {
  return (
    <div role="status" aria-label={label} className="space-y-2.5 py-4">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-4 animate-pulse rounded-full bg-[#e6e6e8]" />
      ))}
      <span className="sr-only">{label}</span>
    </div>
  );
}

export function EmptyState({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}): ReactNode {
  return (
    <div className="rounded-[28px] border border-dashed border-[#d6d6d6] bg-[#ffffff] p-8 text-center">
      <p className="font-semibold text-[#1d1d1f] tracking-tight">{title}</p>
      {children !== undefined && <div className="mt-2 text-sm text-[#707070]">{children}</div>}
    </div>
  );
}

export function StatusPill({ status }: { status: string }): ReactNode {
  const icons: Record<string, string> = {
    queued: "◔",
    running: "◑",
    succeeded: "✓",
    failed: "✗",
    unavailable: "?",
    cancelled: "—",
  };
  const icon = icons[status] ?? "?";
  const isGood = status === "succeeded";
  const isWarn = status === "queued" || status === "running";
  const isErr = status === "failed";

  const colorClass = isGood
    ? "text-[#0071e3] border-[#0071e3]/30 bg-[#0071e3]/5"
    : isWarn
      ? "text-[#b64400] border-[#b64400]/30 bg-[#b64400]/5"
      : isErr
        ? "text-[#d70015] border-[#d70015]/30 bg-[#d70015]/5"
        : "text-[#707070] border-[#e6e6e8] bg-[#ffffff]";

  return (
    <span
      role="img"
      aria-label={`Status: ${status}`}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium tracking-tight ${colorClass}`}
    >
      <span aria-hidden="true" className="font-bold">
        {icon}
      </span>
      {status}
    </span>
  );
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(): void {
    // No telemetry SDKs in the workbench; the fallback below is the report.
  }

  render(): ReactNode {
    if (this.state.error !== null) {
      return (
        <div
          role="alert"
          className="m-4 rounded-[28px] border border-[#d70015]/30 bg-[#ffffff] p-6 text-[#1d1d1f]"
        >
          <p className="font-semibold text-[#d70015]">Something went wrong in this view.</p>
          <p className="mt-1 text-sm text-[#707070]">{this.state.error.message}</p>
          <button
            type="button"
            className="apple-btn-secondary mt-4"
            onClick={() => this.setState({ error: null })}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
