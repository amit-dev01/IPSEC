import { useSyncExternalStore } from "react";

import type { MeResponse } from "@/api/client";
import { clearAccessToken, setAccessToken } from "@/api/token";

export type Role = "admin" | "analyst" | "viewer";

export interface Session {
  token: string;
  user: MeResponse;
}

let session: Session | null = null;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

export function getSession(): Session | null {
  return session;
}

export function startSession(token: string, user: MeResponse): void {
  setAccessToken(token);
  session = { token, user };
  emit();
}

/** Wipes the in-memory token + identity. Callers also clear the query cache. */
export function endSession(): void {
  clearAccessToken();
  session = null;
  emit();
}

export function useSession(): Session | null {
  return useSyncExternalStore(
    (onChange) => {
      listeners.add(onChange);
      return () => listeners.delete(onChange);
    },
    () => session,
    () => session,
  );
}

export function roleOf(user: MeResponse | null): Role | null {
  if (user === null) return null;
  return user.role === "admin" || user.role === "analyst" || user.role === "viewer"
    ? user.role
    : null;
}
