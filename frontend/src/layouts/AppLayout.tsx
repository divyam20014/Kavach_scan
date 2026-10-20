import { AppShell, Burger, Divider, Group, NavLink, ScrollArea, Stack, Text, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { NavLink as RouterNavLink, Outlet, useLocation } from "react-router-dom";
import { useVersion } from "../api/hooks";
import { KillSwitchControl } from "../components/JobControls";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/projects", label: "Projects" },
  { to: "/assets", label: "Assets" },
  { to: "/scans", label: "Scans" },
  { to: "/findings", label: "Findings" },
  { to: "/audit", label: "Audit log" },
  { to: "/settings", label: "Settings & storage" },
  { to: "/help", label: "Help & limitations" },
];

// Listed honestly as unavailable instead of rendering placeholder pages or controls.
const NOT_YET = [
  { label: "API specifications", phase: "Phase 07" },
  { label: "Imports", phase: "Phase 08" },
  { label: "Reports", phase: "Phase 10" },
  { label: "Integrations / tools", phase: "Phase 11" },
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
      <AppShell.Header>
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
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" aria-label="Toggle navigation" />
            <Title order={2} size="h4">
              VAPT Workbench
            </Title>
          </Group>
          <Group gap="md">
            <KillSwitchControl />
            <Text size="xs" c="dimmed">
              Local only · {version.data ? `v${version.data.version}` : "…"}
            </Text>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm" aria-label="Main navigation">
        <AppShell.Section grow component={ScrollArea}>
          <nav>
            {NAV.map((item) => (
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
          </nav>
          <Divider my="sm" />
          <Stack gap={4} px="sm" aria-label="Modules not available yet" role="group">
            <Text size="xs" fw={600} c="dimmed" tt="uppercase">
              Not available yet
            </Text>
            {NOT_YET.map((item) => (
              <Text size="sm" c="dimmed" key={item.label}>
                {item.label} <Text span size="xs">({item.phase})</Text>
              </Text>
            ))}
          </Stack>
        </AppShell.Section>
        <AppShell.Section>
          <Text size="xs" c="dimmed" px="sm">
            Web + attack-surface scanners ready; API scanner arrives in Phase 07.
          </Text>
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
