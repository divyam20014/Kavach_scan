import { Card, SimpleGrid, Stack, Text, Title, UnstyledButton } from "@mantine/core";
import { useNavigate } from "react-router-dom";
import { useAppMode } from "../lib/mode";

interface ModeOption {
  mode: "vapt" | "repo";
  title: string;
  description: string;
  to: string;
}

const OPTIONS: ModeOption[] = [
  {
    mode: "vapt",
    title: "VAPT Scan",
    description:
      "Projects, authorization and scope, web application / attack surface / API security scanning, findings, reports.",
    to: "/",
  },
  {
    mode: "repo",
    title: "Repository Scan",
    description: "Scan a local repository or a git URL for code, secret and dependency issues. No scope or authorization setup needed.",
    to: "/repo-scan",
  },
];

/** The app's landing choice (TBD-116): two entirely separate feature areas, never shown
 * together. Once chosen, the mode is remembered (`useAppMode`) and this page is skipped on
 * future visits -- see the "Switch mode" control in `AppLayout`'s header. */
export function ModeSelectPage() {
  const [, setMode] = useAppMode();
  const navigate = useNavigate();

  const choose = (option: ModeOption) => {
    setMode(option.mode);
    navigate(option.to, { replace: true });
  };

  return (
    <Stack align="center" gap="xl" py="xl">
      <Stack align="center" gap={4}>
        <Title order={1} size="h2">
          What do you want to do?
        </Title>
        <Text c="dimmed" ta="center" maw={520}>
          Choose a feature area to continue. You can switch later from the header.
        </Text>
      </Stack>
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg" maw={720} w="100%">
        {OPTIONS.map((option) => (
          <UnstyledButton key={option.mode} onClick={() => choose(option)} aria-label={option.title}>
            <Card withBorder p="xl" h="100%">
              <Title order={2} size="h3" mb="xs">
                {option.title}
              </Title>
              <Text size="sm" c="dimmed">
                {option.description}
              </Text>
            </Card>
          </UnstyledButton>
        ))}
      </SimpleGrid>
    </Stack>
  );
}
