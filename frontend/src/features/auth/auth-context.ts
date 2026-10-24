import { createContext, useContext } from "react";

import type { Role } from "@/features/auth/auth-store";

export interface AuthContextValue {
  isAuthenticated: boolean;
  email: string | null;
  organizationId: string | null;
  role: Role | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
