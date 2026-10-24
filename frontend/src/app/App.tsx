import { QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";

import { createQueryClient } from "@/app/query-client";
import Shell from "@/app/Shell";
import { ToastProvider } from "@/app/toast";
import { ErrorBoundary } from "@/components/ui";
import AdminPage from "@/features/admin/AdminPage";
import AnalysesPage from "@/features/analyses/AnalysesPage";
import AnalysisDetailPage from "@/features/analyses/AnalysisDetailPage";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { LoginPage } from "@/features/auth/LoginPage";
import OverviewPage from "@/features/auth/OverviewPage";
import { RequireAction, RequireAuth, RequireRole } from "@/features/auth/guards";
import CaptureDetailPage from "@/features/captures/CaptureDetailPage";
import CapturesPage from "@/features/captures/CapturesPage";
import DatasetPage from "@/features/dataset/DatasetPage";

export default function App(): ReactNode {
  const [queryClient] = useState(createQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <ErrorBoundary>
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
                  <Route path="captures/:captureId" element={<CaptureDetailPage />} />
                  <Route path="analyses" element={<AnalysesPage />} />
                  <Route path="analyses/:analysisId" element={<AnalysisDetailPage />} />
                  <Route
                    path="dataset"
                    element={
                      <RequireAction action="dataset:export">
                        <DatasetPage />
                      </RequireAction>
                    }
                  />
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
            </ErrorBoundary>
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
