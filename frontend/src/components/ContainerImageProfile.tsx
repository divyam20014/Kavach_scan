import { Alert, NumberInput, Stack, Text, TextInput } from "@mantine/core";
import type { ScanParams } from "../api/types";
import { AdvancedOptions } from "./AdvancedOptions";

export interface ContainerImageOptions {
  image: string;
  timeout_minutes: number;
}

export const DEFAULT_CONTAINER_IMAGE_OPTIONS: ContainerImageOptions = {
  image: "",
  timeout_minutes: 5,
};

/** Only values that differ from the backend's own defaults are sent, consistent with the
 * other scan-profile components' own convention. */
export function containerImageParams(o: ContainerImageOptions): ScanParams {
  const p: ScanParams = { image: o.image.trim() };
  if (o.timeout_minutes !== DEFAULT_CONTAINER_IMAGE_OPTIONS.timeout_minutes) p.timeout_minutes = o.timeout_minutes;
  return p;
}

export function ContainerImageOptionsPanel({
  value,
  onChange,
}: {
  value: ContainerImageOptions;
  onChange: (v: ContainerImageOptions) => void;
}) {
  const set = <K extends keyof ContainerImageOptions>(k: K, v: ContainerImageOptions[K]) => onChange({ ...value, [k]: v });
  return (
    <Stack gap="xs" aria-label="Container image scan options" role="group">
      <Alert color="blue" variant="light" role="note">
        The image must already be pulled or built on this machine's Docker daemon (<code>docker pull</code>/<code>docker build</code>) — this scan never pulls an image from a registry itself.
      </Alert>
      <TextInput
        label="Image reference"
        description="e.g. myapp:1.2.3, or a locally-tagged image from your own registry"
        placeholder="myapp:1.2.3"
        value={value.image}
        onChange={(e) => set("image", e.currentTarget.value)}
      />
      <AdvancedOptions>
        <NumberInput
          label="Timeout (minutes)"
          min={1}
          max={60}
          value={value.timeout_minutes}
          onChange={(v) => set("timeout_minutes", typeof v === "number" ? v : DEFAULT_CONTAINER_IMAGE_OPTIONS.timeout_minutes)}
        />
      </AdvancedOptions>
      <Text size="sm" c="dimmed">
        Trivy's vulnerability database must have been downloaded once from Integrations before this scan can run.
      </Text>
    </Stack>
  );
}
