import { useSyncExternalStore } from "react";

import type { MeResponse } from "@/api/client";
import { clearAccessToken, setAccessToken } from "@/api/token";

export type Role = "admin" | "analyst" | "viewer";

export interface Session {
  token: string;
  user: MeResponse;
}

const SESSION_STORAGE_KEY = "ipsec_auth_session";

function restoreSession(): Session | null {
  if (typeof window === "undefined" || !window.sessionStorage) return null;
  try {
    const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Session;
    if (parsed && parsed.token && parsed.user) {
      setAccessToken(parsed.token);
      return parsed;
    }
  } catch {
    // ignore storage error
  }
  return null;
}

let session: Session | null = restoreSession();
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
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
    }
  } catch {
    // ignore storage error
  }
  emit();
}

/** Wipes the in-memory token + identity. Callers also clear the query cache. */
export function endSession(): void {
  clearAccessToken();
  session = null;
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
  } catch {
    // ignore storage error
  }
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
