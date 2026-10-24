import { QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Suspense, lazy, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";

import { createQueryClient } from "@/app/query-client";
import Shell from "@/app/Shell";
import { ToastProvider } from "@/app/toast";
import { ErrorBoundary, Skeleton } from "@/components/ui";
import { AuthProvider } from "@/features/auth/AuthProvider";
import OverviewPage from "@/features/auth/OverviewPage";
import { RequireAction, RequireRole } from "@/features/auth/guards";
import CapturesPage from "@/features/captures/CapturesPage";

// Route-level code splitting: heavy analysis/admin/report modules load on
// demand so the login/overview bundle stays small.
const AnalysesPage = lazy(() => import("@/features/analyses/AnalysesPage"));
const AnalysisDetailPage = lazy(() => import("@/features/analyses/AnalysisDetailPage"));
const ReportCenterPage = lazy(() => import("@/features/analyses/ReportCenterPage"));
const CaptureDetailPage = lazy(() => import("@/features/captures/CaptureDetailPage"));
const DatasetPage = lazy(() => import("@/features/dataset/DatasetPage"));
const AdminPage = lazy(() => import("@/features/admin/AdminPage"));
const AuditPage = lazy(() => import("@/features/admin/AuditPage"));
const LiveCapturePage = lazy(() => import("@/features/admin/LiveCapturePage"));

function Lazy({ children }: { children: ReactNode }): ReactNode {
  return <Suspense fallback={<Skeleton label="Loading view" rows={4} />}>{children}</Suspense>;
}

export default function App(): ReactNode {
  const [queryClient] = useState(createQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <ErrorBoundary>
              <Routes>
                {/* Login removed: the site opens directly in Demo Mode. */}
                <Route path="/login" element={<Navigate to="/" replace />} />
                <Route path="/" element={<Shell />}>
                  <Route index element={<OverviewPage />} />
                  <Route path="captures" element={<CapturesPage />} />
                  <Route
                    path="captures/:captureId"
                    element={
                      <Lazy>
                        <CaptureDetailPage />
                      </Lazy>
                    }
                  />
                  <Route
                    path="analyses"
                    element={
                      <Lazy>
                        <AnalysesPage />
                      </Lazy>
                    }
                  />
                  <Route
                    path="analyses/:analysisId"
                    element={
                      <Lazy>
                        <AnalysisDetailPage />
                      </Lazy>
                    }
                  />
                  <Route
                    path="analyses/:analysisId/report"
                    element={
                      <Lazy>
                        <ReportCenterPage />
                      </Lazy>
                    }
                  />
                  <Route
                    path="dataset"
                    element={
                      <Lazy>
                        <RequireAction action="dataset:export">
                          <DatasetPage />
                        </RequireAction>
                      </Lazy>
                    }
                  />
                  <Route
                    path="admin"
                    element={
                      <RequireRole roles={["admin"]}>
                        <Lazy>
                          <AdminPage />
                        </Lazy>
                      </RequireRole>
                    }
                  />
                  <Route
                    path="admin/audit"
                    element={
                      <RequireRole roles={["admin"]}>
                        <Lazy>
                          <AuditPage />
                        </Lazy>
                      </RequireRole>
                    }
                  />
                  <Route
                    path="admin/live-capture"
                    element={
                      <RequireRole roles={["admin"]}>
                        <Lazy>
                          <LiveCapturePage />
                        </Lazy>
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
