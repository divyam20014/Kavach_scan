import { Card, Group, Stack, Text, UnstyledButton } from "@mantine/core";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/** A clickable KPI that opens a pre-filtered view. The value always comes from the API. */
export function KpiCard({ label, value, to, hint, testId }: { label: string; value: number; to: string; hint?: ReactNode; testId?: string }) {
  return (
    <UnstyledButton
      component={Link}
      to={to}
      aria-label={`${label}: ${value}. Open filtered view`}
      data-testid={testId}
      style={{ display: "block", borderRadius: 8 }}
    >
      <Card withBorder padding="md" radius="md" h="100%">
        <Stack gap={4}>
          <Text size="sm" c="dimmed">
            {label}
          </Text>
          <Group justify="space-between" align="baseline">
            <Text fz={28} fw={700} lh={1}>
              {value}
            </Text>
            <Text size="xs" c="blue" aria-hidden="true">
              View →
            </Text>
          </Group>
          {hint && (
            <Text size="xs" c="dimmed">
              {hint}
            </Text>
          )}
        </Stack>
      </Card>
    </UnstyledButton>
  );
}
