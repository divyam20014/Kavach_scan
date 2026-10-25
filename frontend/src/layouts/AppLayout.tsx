import { AppShell, Burger, Divider, Group, NavLink, ScrollArea, Text, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { NavLink as RouterNavLink, Outlet, useLocation } from "react-router-dom";
import { useVersion } from "../api/hooks";
import { KillSwitchControl } from "../components/JobControls";

// Three sections, in the order an operator actually works: start a project, review results
// across projects, then system-level pages. Every entry here is a real, implemented route —
// project-scoped pages (imports, reports, attack surface, API specs) are reached from the
// project itself (see ProjectDetailPage) rather than listed again at the top level.
const NAV_SECTIONS: { label: string; items: { to: string; label: string; end?: boolean }[] }[] = [
  {
    label: "Workspace",
    items: [
      { to: "/", label: "Dashboard", end: true },
      { to: "/projects", label: "Projects" },
    ],
  },
  {
    label: "Records",
    items: [
      { to: "/findings", label: "Findings" },
      { to: "/assets", label: "Assets" },
      { to: "/scans", label: "Scans" },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/integrations", label: "Integrations & CVE data" },
      { to: "/audit", label: "Audit log" },
      { to: "/settings", label: "Settings & storage" },
      { to: "/help", label: "Help & limitations" },
    ],
  },
];

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure();
  const version = useVersion();
  const location = useLocation();

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 248, breakpoint: "sm", collapsed: { mobile: !opened } }}
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
              <Title order={2} size="h4" c="white">
                VAPT Workbench
              </Title>
            </Group>
          </Group>
          <Group gap="md">
            <KillSwitchControl />
            <Text size="xs" c="gray.4">
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
              <Text size="xs" fw={600} c="dimmed" tt="uppercase" px="sm" mb={4}>
                {section.label}
              </Text>
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  component={RouterNavLink}
                  to={item.to}
                  end={item.end}
                  label={item.label}
                  active={item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)}
                  onClick={close}
                />
              ))}
            </div>
          ))}
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <main id="main" tabIndex={-1} style={{ outline: "none", maxWidth: 1280 }}>
          <Outlet />
        </main>
      </AppShell.Main>
    </AppShell>
  );
}
