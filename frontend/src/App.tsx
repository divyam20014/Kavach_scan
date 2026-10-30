import { createTheme, MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { ApiError } from "./api/client";
import { AppLayout } from "./layouts/AppLayout";
import { DashboardPage } from "./pages/DashboardPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { SurfacePage } from "./pages/SurfacePage";
import { ApiSpecPage } from "./pages/ApiSpecPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsWorkbenchPage } from "./pages/FindingsWorkbenchPage";
import { ImportsPage } from "./pages/ImportsPage";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { ModeSelectPage } from "./pages/ModeSelectPage";
import { ProjectWizardPage } from "./pages/ProjectWizardPage";
import { ReportBuilderPage } from "./pages/ReportBuilderPage";
import { RepositoryScanStartPage } from "./pages/RepositoryScanStartPage";
import { AssetsPage, ScansPage } from "./pages/RecordPages";
import { AuditPage, HelpPage, NotFoundPage, SettingsPage } from "./pages/SystemPages";
import { useAppMode } from "./lib/mode";

export const theme = createTheme({
  primaryColor: "blue",
  defaultRadius: "md",
  fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
  focusRing: "always",
  // A restrained, consistent heading scale instead of each page picking its own `size`.
  headings: {
    sizes: {
      h1: { fontSize: "1.5rem", fontWeight: "700" },
      h2: { fontSize: "1.25rem", fontWeight: "600" },
      h3: { fontSize: "1.1rem", fontWeight: "600" },
      h4: { fontSize: "1rem", fontWeight: "600" },
    },
  },
  // Consistent card elevation and borders app-wide instead of each page choosing its own look.
  components: {
    Card: {
      defaultProps: { shadow: "xs", withBorder: true },
    },
    Table: {
      defaultProps: { verticalSpacing: "xs" },
    },
    Tooltip: {
      defaultProps: { openDelay: 200 },
    },
  },
});

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Never retry client errors (4xx); retry transient failures once.
        retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 1,
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function Providers({ children, client }: { children: ReactNode; client: QueryClient }) {
  return (
    <QueryClientProvider client={client}>
      <MantineProvider theme={theme} defaultColorScheme="light">
        <Notifications position="top-right" />
        {children}
      </MantineProvider>
    </QueryClientProvider>
  );
}

/** The app's index route: no mode chosen yet -> the mode chooser; "vapt" -> the dashboard
 * (unchanged route); "repo" -> straight into the repository-scan flow (its home is a
 * different route, `/repo-scan`, not `/`). See `lib/mode.ts` and TBD-116. */
function HomeRoute() {
  const [mode] = useAppMode();
  if (mode === "repo") return <Navigate to="/repo-scan" replace />;
  if (mode === "vapt") return <DashboardPage />;
  return <ModeSelectPage />;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<HomeRoute />} />
        <Route path="projects" element={<ProjectsPage />} />
        <Route path="projects/new" element={<ProjectWizardPage />} />
        <Route path="repo-scan" element={<RepositoryScanStartPage />} />
        <Route path="projects/:projectId" element={<ProjectDetailPage />} />
        <Route path="projects/:projectId/edit" element={<ProjectWizardPage />} />
        <Route path="projects/:projectId/scans/:scanId" element={<ScanDetailPage />} />
        <Route path="projects/:projectId/surface" element={<SurfacePage />} />
        <Route path="projects/:projectId/api-specs" element={<ApiSpecPage />} />
        <Route path="projects/:projectId/imports" element={<ImportsPage />} />
        <Route path="projects/:projectId/reports" element={<ReportBuilderPage />} />
        <Route path="projects/:projectId/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="findings" element={<FindingsWorkbenchPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="help" element={<HelpPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
