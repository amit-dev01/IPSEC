import { useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useCallback, useEffect } from "react";
import { useNavigate } from "react-router";

import { ApiError, fetchMe, login as apiLogin } from "@/api/client";
import { setAccessToken, setUnauthorizedHandler } from "@/api/token";
import { AuthContext } from "@/features/auth/auth-context";
import type { AuthContextValue } from "@/features/auth/auth-context";
import { endSession, startSession, useSession } from "@/features/auth/auth-store";
import { roleOf } from "@/features/auth/auth-store";

export function AuthProvider({ children }: { children: ReactNode }): ReactNode {
  const session = useSession();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const logout = useCallback((): void => {
    // Order matters: token first, then wipe every cached tenant datum,
    // then leave the protected area. Zero previous-tenant data remains.
    endSession();
    queryClient.clear();
    void navigate("/", { replace: true });
  }, [navigate, queryClient]);

  // Any 401 anywhere in the app resets the session exactly like logout.
  useEffect(() => {
    setUnauthorizedHandler(logout);
    return () => setUnauthorizedHandler(null);
  }, [logout]);

  const login = useCallback(
    async (email: string, password: string): Promise<void> => {
      const tokenResponse = await apiLogin(email, password);
      // Set the token before /auth/me so the request is authenticated; if
      // anything fails, endSession wipes the partial state again.
      setAccessToken(tokenResponse.access_token);
      try {
        const user = await fetchMe();
        startSession(tokenResponse.access_token, user);
      } catch (error) {
        endSession();
        queryClient.clear();
        throw error instanceof ApiError
          ? error
          : new ApiError({
              status: 0,
              code: null,
              title: "Sign-in failed",
              detail: "Could not load your profile. Please try again.",
            });
      }
      void navigate("/", { replace: true });
    },
    [navigate, queryClient],
  );

  // Demo Mode: the website no longer has a login screen. Without a real
  // session the UI runs under a clearly-labeled demo identity so every
  // screen is reachable; the backend API still enforces its own auth and
  // its 401 responses surface as data errors, never fabricated data.
  const value: AuthContextValue = {
    isAuthenticated: session !== null,
    isDemoMode: session === null,
    email: session?.user.email ?? "demo@ipsec.lab",
    organizationId: session?.user.organization_id ?? "demo-organization",
    role: roleOf(session?.user ?? null) ?? "admin",
    login,
    logout,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
