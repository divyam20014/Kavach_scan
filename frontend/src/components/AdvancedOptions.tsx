import { Button, Collapse, Stack } from "@mantine/core";
import { useState, type ReactNode } from "react";

/** A shared "Advanced options" disclosure for scan-profile panels: the handful of fields
 * most operators leave at their safe defaults stay out of the way until asked for, instead
 * of every control appearing flat on every scan start (reused by every current and future
 * scan-type profile panel, not reimplemented per module). Collapsed by default. */
export function AdvancedOptions({ children, defaultOpen = false }: { children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <Button
        variant="subtle"
        size="xs"
        px={4}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        rightSection={
          <span aria-hidden="true" style={{ display: "inline-block", transform: open ? "rotate(180deg)" : "none", transition: "transform 120ms" }}>
            ▾
          </span>
        }
      >
        {open ? "Hide advanced options" : "Advanced options"}
      </Button>
      <Collapse in={open}>
        <Stack gap="xs" mt="xs">
          {children}
        </Stack>
      </Collapse>
    </div>
  );
}
