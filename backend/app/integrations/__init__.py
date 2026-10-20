"""External integrations. Only modules in this package may start processes (and, from
Phase 05, open network connections); every target they touch must be authorized by
`app.scope.ScopeGuard` first."""
