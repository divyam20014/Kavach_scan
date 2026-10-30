import { useLocalStorage } from "@mantine/hooks";

/** "" means no mode has been chosen yet (show the chooser). Stored per-browser, never sent
 * to the backend -- this is a UI-only split between the two feature areas, not a security
 * boundary (both areas hit the same local, single-operator API). */
export type AppMode = "vapt" | "repo" | "";

const KEY = "kavach-app-mode";

export function useAppMode() {
  // getInitialValueInEffect: false -- read the real stored value synchronously on first
  // render. This app is client-only (no SSR), so there's no hydration-mismatch risk to
  // avoid, and the default two-pass behavior raced with the deep-link mode inference in
  // AppLayout's useModeGuard: it would briefly see the "" default, infer a mode from the
  // current path, and overwrite a real stored value before this hook's own effect restored
  // it (confirmed directly: a "vapt" page reached via /repo-scan with mode="vapt" already
  // stored got silently flipped to "repo").
  return useLocalStorage<AppMode>({ key: KEY, defaultValue: "", getInitialValueInEffect: false });
}
