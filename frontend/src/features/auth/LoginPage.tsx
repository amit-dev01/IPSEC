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

  async function onSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    if (email.trim() === "" || password === "") {
      setError("Email and password are required.");
      return;
    }
    setSubmitting(true);
    try {
      await login(email.trim(), password);
    } catch (caught) {
      // No credential details are ever surfaced; only safe server codes.
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

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center p-6">
      <h1 className="text-2xl font-semibold">IPsec Analyzer</h1>
      <p className="mt-1 text-sm text-ink-muted">Analyst workbench sign-in</p>
      <form
        onSubmit={(e) => void onSubmit(e)}
        noValidate
        className="mt-6 space-y-4"
        aria-describedby={error !== null ? errorId : undefined}
      >
        <div>
          <label htmlFor={emailId} className="mb-1 block text-sm font-medium">
            Email
          </label>
          <input
            id={emailId}
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded border border-line bg-surface-raised px-3 py-2"
          />
        </div>
        <div>
          <label htmlFor={passwordId} className="mb-1 block text-sm font-medium">
            Password
          </label>
          <input
            id={passwordId}
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border border-line bg-surface-raised px-3 py-2"
          />
        </div>
        {error !== null && (
          <p
            id={errorId}
            role="alert"
            className="rounded border border-sev-critical px-3 py-2 text-sm text-sev-critical"
          >
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-accent px-3 py-2 font-medium text-accent-ink disabled:opacity-50"
        >
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="mt-6 text-xs text-ink-muted">
        Sessions are held in memory only: refreshing this page requires signing in again. This
        protects analyst tokens from being persisted in browser storage.
      </p>
    </main>
  );
}
