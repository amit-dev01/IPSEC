import { QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";

import { createQueryClient } from "@/app/query-client";
import Shell from "@/app/Shell";
import AdminPage from "@/features/admin/AdminPage";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { RequireAuth, RequireRole } from "@/features/auth/guards";
import { LoginPage } from "@/features/auth/LoginPage";
import OverviewPage from "@/features/auth/OverviewPage";
import CapturesPage from "@/features/captures/CapturesPage";

export default function App(): ReactNode {
  const [queryClient] = useState(createQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/"
              element={
                <RequireAuth>
                  <Shell />
                </RequireAuth>
              }
            >
              <Route index element={<OverviewPage />} />
              <Route path="captures" element={<CapturesPage />} />
              <Route
                path="admin"
                element={
                  <RequireRole roles={["admin"]}>
                    <AdminPage />
                  </RequireRole>
                }
              />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
