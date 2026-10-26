/** Shared layout tokens for the app shell (header/sidebar), so sizing lives in one place
 * instead of being repeated as magic numbers across `App.tsx`/`AppLayout.tsx`. */
export const LAYOUT = {
  headerHeight: 56,
  sidebarWidth: 248,
  sidebarCollapsedWidth: 64,
  contentMaxWidth: 1280,
} as const;
