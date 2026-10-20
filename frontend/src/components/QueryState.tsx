import { Alert, Button, Center, Loader, Stack, Text, Title } from "@mantine/core";
import type { ReactNode } from "react";
import { ApiError } from "../api/client";

export function ErrorAlert({ error, onRetry, title = "Something went wrong" }: { error: unknown; onRetry?: () => void; title?: string }) {
  const message = error instanceof ApiError ? error.describe() : "Unexpected error.";
  const correlation = error instanceof ApiError ? error.correlationId : null;
  return (
    <Alert color="red" title={title} role="alert" variant="light">
      <Stack gap="xs">
        <Text size="sm">{message}</Text>
        {correlation && (
          <Text size="xs" c="dimmed">
            Reference: {correlation}
          </Text>
        )}
        {onRetry && (
          <Button size="xs" variant="light" color="red" onClick={onRetry} w="fit-content">
            Retry
          </Button>
        )}
      </Stack>
    </Alert>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <Center py="xl" role="status" aria-live="polite">
      <Stack align="center" gap="xs">
        <Loader size="sm" />
        <Text size="sm" c="dimmed">
          {label}
        </Text>
      </Stack>
    </Center>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <Center py="xl">
      <Stack align="center" gap="xs" maw={520} ta="center">
        <Title order={2} size="h4">
          {title}
        </Title>
        {children && (
          <Text size="sm" c="dimmed">
            {children}
          </Text>
        )}
        {action}
      </Stack>
    </Center>
  );
}

/** Standard loading / error / content switch for a TanStack query. */
export function QueryState<T>({
  query,
  children,
  loadingLabel,
}: {
  query: { isPending: boolean; isError: boolean; error: unknown; data: T | undefined; refetch: () => unknown };
  children: (data: T) => ReactNode;
  loadingLabel?: string;
}) {
  if (query.isPending) return <Loading label={loadingLabel} />;
  if (query.isError || query.data === undefined) return <ErrorAlert error={query.error} onRetry={() => void query.refetch()} />;
  return <>{children(query.data)}</>;
}
