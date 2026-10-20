import { Anchor, Breadcrumbs, Group, Stack, Text, Title } from "@mantine/core";
import { useEffect, type ReactNode } from "react";
import { Link } from "react-router-dom";

export interface Crumb {
  label: string;
  to?: string;
}

export function PageHeader({
  title,
  description,
  crumbs = [],
  actions,
}: {
  title: string;
  description?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
}) {
  useEffect(() => {
    document.title = `${title} · VAPT Workbench`;
  }, [title]);
  return (
    <Stack gap="xs" mb="lg">
      {crumbs.length > 0 && (
        <nav aria-label="Breadcrumb">
        <Breadcrumbs>
          {crumbs.map((c) =>
            c.to ? (
              <Anchor component={Link} to={c.to} key={c.label} size="sm">
                {c.label}
              </Anchor>
            ) : (
              <Text size="sm" key={c.label} aria-current="page">
                {c.label}
              </Text>
            ),
          )}
        </Breadcrumbs>
        </nav>
      )}
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <div>
          <Title order={1} size="h2">
            {title}
          </Title>
          {description && (
            <Text c="dimmed" size="sm" mt={4}>
              {description}
            </Text>
          )}
        </div>
        {actions && <Group gap="sm">{actions}</Group>}
      </Group>
    </Stack>
  );
}
