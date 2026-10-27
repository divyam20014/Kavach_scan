import { ActionIcon, AppShell, Burger, Divider, Group, NavLink, ScrollArea, Text, Title, Tooltip } from "@mantine/core";
import { useDisclosure, useLocalStorage } from "@mantine/hooks";
import type { ReactNode } from "react";
import { NavLink as RouterNavLink, Outlet, useLocation } from "react-router-dom";
import { useVersion } from "../api/hooks";
import { KillSwitchControl } from "../components/JobControls";
import { LAYOUT } from "../theme/tokens";

// Minimal inline line-icons (no icon-library dependency added for this) -- one per nav
// item, kept to the same visual weight as the header's own inline shield mark below.
function Icon({ path, viewBox = "0 0 24 24" }: { path: ReactNode; viewBox?: string }) {
  return (
    <svg width="18" height="18" viewBox={viewBox} fill="none" aria-hidden="true">
      {path}
    </svg>
  );
}
const ICONS: Record<string, ReactNode> = {
  dashboard: <Icon path={<path d="M3 13h8V3H3zm10 8h8V3h-8zM3 21h8v-6H3zm10-6v6h8v-6z" fill="currentColor" />} />,
  projects: <Icon path={<path d="M3 7a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />} />,
  findings: <Icon path={<path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z M12 8v5 M12 16.2v.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />} />,
  assets: <Icon path={<><rect x="3" y="4" width="18" height="5" rx="1" stroke="currentColor" strokeWidth="1.6" /><rect x="3" y="11" width="18" height="5" rx="1" stroke="currentColor" strokeWidth="1.6" /><rect x="3" y="18" width="18" height="2.5" rx="1" stroke="currentColor" strokeWidth="1.6" /></>} />,
  scans: <Icon path={<><circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6" /><path d="m20 20-4.3-4.3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></>} />,
  integrations: <Icon path={<path d="M9 2v4M15 2v4M6 8h12l-1 11a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2z" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />} />,
  audit: <Icon path={<><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" /><path d="M12 7v5l3 2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></>} />,
  settings: <Icon path={<><circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.6" /><path d="M12 3v2.5M12 18.5V21M4.2 7.5l2.1 1.3M17.7 15.2l2.1 1.3M4.2 16.5l2.1-1.3M17.7 8.8l2.1-1.3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></>} />,
  help: <Icon path={<><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" /><path d="M9.5 9.3a2.5 2.5 0 1 1 3.9 2.1c-.9.6-1.4 1-1.4 2.1M12 17v.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></>} />,
  repo: <Icon path={<path d="M8 6 3 12l5 6M16 6l5 6-5 6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />} />,
};

// Three sections, in the order an operator actually works: start a project, review results
// across projects, then system-level pages. Every entry here is a real, implemented route —
// project-scoped pages (imports, reports, attack surface, API specs) are reached from the
// project itself (see ProjectDetailPage) rather than listed again at the top level.
const NAV_SECTIONS: { label: string; items: { to: string; label: string; icon: string; end?: boolean }[] }[] = [
  {
    label: "Workspace",
    items: [
      { to: "/", label: "Dashboard", icon: "dashboard", end: true },
      { to: "/projects", label: "Projects", icon: "projects" },
      { to: "/repo-scan", label: "Repository Scan", icon: "repo" },
    ],
  },
  {
    label: "Records",
    items: [
      { to: "/findings", label: "Findings", icon: "findings" },
      { to: "/assets", label: "Assets", icon: "assets" },
      { to: "/scans", label: "Scans", icon: "scans" },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/integrations", label: "Integrations & CVE data", icon: "integrations" },
      { to: "/audit", label: "Audit log", icon: "audit" },
      { to: "/settings", label: "Settings & storage", icon: "settings" },
      { to: "/help", label: "Help & limitations", icon: "help" },
    ],
  },
];

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure();
  // Desktop-only icon-rail collapse; remembered per browser, purely a display convenience
  // (never read back by the app, so a cleared/unavailable storage degrades to "expanded").
  const [collapsed, setCollapsed] = useLocalStorage({ key: "kavach-nav-collapsed", defaultValue: false });
  const version = useVersion();
  const location = useLocation();
  // The icon-rail collapse is a desktop-only display mode -- the mobile drawer (opened via
  // the burger) is a completely different UI (full-width overlay, closed by default) and
  // must always show full labels, regardless of the desktop rail's remembered state.
  const showLabels = !collapsed || opened;

  return (
    <AppShell
      header={{ height: LAYOUT.headerHeight }}
      navbar={{
        width: { base: LAYOUT.sidebarWidth, sm: collapsed ? LAYOUT.sidebarCollapsedWidth : LAYOUT.sidebarWidth },
        breakpoint: "sm",
        collapsed: { mobile: !opened },
      }}
      padding="lg"
    >
      <AppShell.Header className="app-header">
        <a
          href="#main"
          className="skip-link"
          onClick={(e) => {
            e.preventDefault();
            document.getElementById("main")?.focus();
          }}
        >
          Skip to main content
        </a>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Burger
              opened={opened}
              onClick={toggle}
              hiddenFrom="sm"
              size="sm"
              color="white"
              aria-label="Toggle navigation"
            />
            <Group gap={8}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"
                  fill="var(--mantine-color-blue-5)"
                  stroke="var(--mantine-color-blue-3)"
                  strokeWidth="1"
                />
                <path d="m9 12 2 2 4-4" stroke="white" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <Title order={2} size="h4" c="white" visibleFrom="xs">
                VAPT Workbench
              </Title>
            </Group>
          </Group>
          <Group gap="md" wrap="nowrap">
            <KillSwitchControl />
            {/* Non-critical context, dropped first on narrow screens so it never crowds
                or overlaps the safety-critical kill-switch control next to it. */}
            <Text size="xs" c="gray.4" visibleFrom="xs" style={{ whiteSpace: "nowrap" }}>
              Local only · {version.data ? `v${version.data.version}` : "…"}
            </Text>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm" aria-label="Main navigation">
        <AppShell.Section grow component={ScrollArea}>
          {NAV_SECTIONS.map((section, i) => (
            // A plain group, not a nested <nav>: the navbar itself is already the one
            // "Main navigation" landmark; a second nested landmark per section would be
            // a redundant/confusing stop for screen-reader users navigating by landmark.
            <div key={section.label} role="group" aria-label={section.label}>
              {i > 0 && <Divider my="sm" />}
              {showLabels && (
                <Text size="xs" fw={600} c="dimmed" tt="uppercase" px="sm" mb={4}>
                  {section.label}
                </Text>
              )}
              {section.items.map((item) => {
                const active = item.end ? location.pathname === item.to : location.pathname.startsWith(item.to);
                const link = (
                  <NavLink
                    key={item.to}
                    component={RouterNavLink}
                    to={item.to}
                    end={item.end}
                    label={showLabels ? item.label : undefined}
                    aria-label={showLabels ? undefined : item.label}
                    leftSection={ICONS[item.icon]}
                    active={active}
                    onClick={close}
                    style={showLabels ? undefined : { justifyContent: "center" }}
                  />
                );
                return showLabels ? (
                  link
                ) : (
                  <Tooltip key={item.to} label={item.label} position="right" withArrow>
                    {link}
                  </Tooltip>
                );
              })}
            </div>
          ))}
        </AppShell.Section>
        <AppShell.Section visibleFrom="sm">
          <Divider mb="xs" />
          <Tooltip label={collapsed ? "Expand navigation" : "Collapse navigation"} position="right">
            <ActionIcon variant="subtle" color="gray" onClick={() => setCollapsed((v) => !v)} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"} mx="auto" style={{ display: "flex" }}>
              <Icon path={<path d={collapsed ? "M9 6l6 6-6 6" : "M15 6l-6 6 6 6"} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" fill="none" />} />
            </ActionIcon>
          </Tooltip>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <main id="main" tabIndex={-1} style={{ outline: "none", maxWidth: LAYOUT.contentMaxWidth }}>
          <Outlet />
        </main>
      </AppShell.Main>
    </AppShell>
  );
}
