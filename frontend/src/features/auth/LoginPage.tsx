import type { FormEvent, ReactNode } from "react";
import { useId, useState } from "react";

import { ApiError } from "@/api/client";
import { useAuth } from "@/features/auth/auth-context";

export function LoginPage(): ReactNode {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const emailId = useId();
  const passwordId = useId();
  const errorId = useId();

  async function performLogin(targetEmail: string, targetPass: string): Promise<void> {
    setError(null);
    if (targetEmail.trim() === "" || targetPass === "") {
      setError("Email and password are required.");
      return;
    }
    setSubmitting(true);
    try {
      await login(targetEmail.trim(), targetPass);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 429) {
        const wait =
          caught.retryAfterSeconds !== null
            ? ` Try again in ${caught.retryAfterSeconds} seconds.`
            : "";
        setError(`Too many sign-in attempts. Please wait before trying again.${wait}`);
      } else if (caught instanceof ApiError && (caught.status === 401 || caught.status === 403)) {
        setError("Invalid credentials or inactive account.");
      } else {
        setError("Sign-in failed. Please check your connection and try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function onSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    await performLogin(email, password);
  }

  function handleQuickRole(roleEmail: string): void {
    setEmail(roleEmail);
    setPassword("demo123");
    void performLogin(roleEmail, "demo123");
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-lg flex-col justify-center px-4 py-12">
      <div className="rounded-2xl border border-line bg-surface-raised p-8 shadow-2xl backdrop-blur transition-all">
        {/* Header with Cyber/Shield Branding */}
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent text-accent-ink shadow-md">
            <svg
              className="h-6 w-6"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-ink">IPsec Analyzer</h1>
            <p className="text-xs text-ink-muted">Analyst workbench sign-in</p>
          </div>
        </div>

        {/* Fake Auth / Demo Notice Banner */}
        <div className="mt-6 rounded-lg border border-accent/30 bg-surface-sunken p-3.5 text-xs">
          <div className="flex items-center gap-2 font-semibold text-accent">
            <span className="flex h-2 w-2 rounded-full bg-accent animate-pulse" />
            <span>Fake Login &amp; No-Auth Mode Active</span>
          </div>
          <p className="mt-1 text-ink-muted">
            Strict authentication is removed. You can sign in using any email and password, or click
            one of the quick role profiles below.
          </p>
        </div>

        {/* Quick Role Selectors */}
        <div className="mt-5">
          <p className="text-xs font-medium uppercase tracking-wider text-ink-muted">
            Instant 1-Click Profiles
          </p>
          <div className="mt-2 grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => handleQuickRole("admin@ipsec.lab")}
              className="group flex flex-col items-center rounded-lg border border-line bg-surface p-2.5 text-center transition hover:border-accent hover:bg-surface-sunken"
            >
              <span className="text-base">🛡️</span>
              <span className="mt-1 text-xs font-semibold text-ink group-hover:text-accent">
                Admin
              </span>
              <span className="text-[10px] text-ink-muted">Full access</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickRole("analyst@ipsec.lab")}
              className="group flex flex-col items-center rounded-lg border border-line bg-surface p-2.5 text-center transition hover:border-accent hover:bg-surface-sunken"
            >
              <span className="text-base">🔬</span>
              <span className="mt-1 text-xs font-semibold text-ink group-hover:text-accent">
                Analyst
              </span>
              <span className="text-[10px] text-ink-muted">Captures/runs</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickRole("viewer@ipsec.lab")}
              className="group flex flex-col items-center rounded-lg border border-line bg-surface p-2.5 text-center transition hover:border-accent hover:bg-surface-sunken"
            >
              <span className="text-base">👁️</span>
              <span className="mt-1 text-xs font-semibold text-ink group-hover:text-accent">
                Viewer
              </span>
              <span className="text-[10px] text-ink-muted">Read-only</span>
            </button>
          </div>
        </div>

        {/* Credentials Form */}
        <form
          onSubmit={(e) => void onSubmit(e)}
          noValidate
          className="mt-6 space-y-4"
          aria-describedby={error !== null ? errorId : undefined}
        >
          <div>
            <label htmlFor={emailId} className="mb-1 block text-sm font-medium text-ink">
              Email
            </label>
            <input
              id={emailId}
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g. admin@ipsec.lab"
              className="w-full rounded-lg border border-line bg-surface px-3.5 py-2.5 text-sm text-ink placeholder:text-ink-muted focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition"
            />
          </div>

          <div>
            <label htmlFor={passwordId} className="mb-1 block text-sm font-medium text-ink">
              Password
            </label>
            <input
              id={passwordId}
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Any password accepted"
              className="w-full rounded-lg border border-line bg-surface px-3.5 py-2.5 text-sm text-ink placeholder:text-ink-muted focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition"
            />
          </div>

          {error !== null && (
            <p
              id={errorId}
              role="alert"
              className="rounded-lg border border-sev-critical/50 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical"
            >
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full cursor-pointer rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-accent-ink shadow transition hover:opacity-90 active:scale-[0.99] disabled:opacity-50"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-ink-muted">
          Connected to backend via automatic same-origin proxy.
        </p>
      </div>
    </main>
  );
}
