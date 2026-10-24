import type { ReactNode } from "react";
import { Component } from "react";

export function Skeleton({ label, rows = 3 }: { label: string; rows?: number }): ReactNode {
  return (
    <div role="status" aria-label={label} className="space-y-2 py-4">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-4 animate-pulse rounded bg-surface-sunken" />
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
    <div className="rounded border border-dashed border-line p-6 text-center">
      <p className="font-medium">{title}</p>
      {children !== undefined && <div className="mt-2 text-sm text-ink-muted">{children}</div>}
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
  return (
    <span
      role="img"
      aria-label={`Status: ${status}`}
      className="inline-flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-xs font-medium"
    >
      <span aria-hidden="true">{icon}</span>
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
        <div role="alert" className="m-4 rounded border border-sev-critical p-4">
          <p className="font-medium">Something went wrong in this view.</p>
          <p className="mt-1 text-sm">{this.state.error.message}</p>
          <button
            type="button"
            className="mt-3 rounded border border-line px-2 py-1 text-sm"
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
