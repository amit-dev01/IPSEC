/**
 * In-memory bearer token holder.
 *
 * The token lives ONLY in this module variable — never localStorage,
 * sessionStorage, cookies, or URLs. A page refresh therefore ends the
 * session and requires re-authentication; that is deliberate (protects
 * analyst tokens from XSS persistence). See docs/frontend-architecture.md.
 */
let accessToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function clearAccessToken(): void {
  accessToken = null;
}

/** Registered by the app shell: clears session state + query caches, routes to /login. */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

export function notifyUnauthorized(): void {
  clearAccessToken();
  unauthorizedHandler?.();
}
