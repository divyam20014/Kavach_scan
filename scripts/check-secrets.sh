#!/usr/bin/env bash
# Blocks a commit/push that introduces a secret-SHAPED literal (Stripe, AWS, GitHub, Slack,
# Google, a PEM private key block, ...), the same class of thing GitHub's push protection
# scans for. It exists because this repo has twice had a push rejected after a test fixture
# happened to match a provider's key format closely enough (see TBD_DECISIONS.md).
#
# Scope: only ADDED lines in a unified diff are checked (lines starting with a single "+",
# excluding the "+++ b/..." file header) — never the whole file, so an already-committed,
# deliberate secret-shaped fixture (e.g. backend/tests/test_redaction.py) is never re-flagged
# just because some other line in that file changed.
#
# Escape hatch: a line containing the literal marker `secret-scan-ignore` is never flagged —
# use it only after confirming by hand that the value is not, and cannot be mistaken for, a
# real credential (prefer building the value from fragments at runtime instead; see
# TBD_DECISIONS.md's entries on this).
#
# Usage: fed a unified diff on stdin; exits 1 and prints every offending line if anything
# matches, exits 0 otherwise. Called by .githooks/pre-commit and .githooks/pre-push.

set -euo pipefail

PATTERN='sk_(live|test)_[A-Za-z0-9]{10,}'
PATTERN+='|pk_(live|test)_[A-Za-z0-9]{10,}'
PATTERN+='|rk_live_[A-Za-z0-9]{10,}'
PATTERN+='|AKIA[0-9A-Z]{16}'
PATTERN+='|gh[pousr]_[A-Za-z0-9]{30,}'
PATTERN+='|github_pat_[A-Za-z0-9_]{30,}'
PATTERN+='|xox[baprs]-[0-9A-Za-z-]{10,}'
PATTERN+='|AIza[0-9A-Za-z_-]{30,}'
PATTERN+='|npm_[A-Za-z0-9]{30,}'
PATTERN+='|-----BEGIN[A-Z ]*PRIVATE KEY-----'

diff_text="$(cat)"

offenders="$(printf '%s\n' "$diff_text" \
  | grep -E '^\+' \
  | grep -Ev '^\+\+\+' \
  | grep -v 'secret-scan-ignore' \
  | grep -E "$PATTERN" || true)"

if [ -n "$offenders" ]; then
  echo "check-secrets: a line added in this change looks like a real credential:" >&2
  echo "$offenders" | sed 's/^/  /' >&2
  echo >&2
  echo "If this is a deliberate, reviewed test fixture (not a real secret), build the value" >&2
  echo 'from fragments at runtime instead of a single literal, e.g.:' >&2
  echo '  not_a_real_key = "-".join(("not", "a", "real", "credential", "0123456789abcdef"))' >&2
  echo "or add the marker 'secret-scan-ignore' on the same line after hand-confirming it is safe." >&2
  exit 1
fi

exit 0
