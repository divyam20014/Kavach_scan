"""Credential-alias resolution for cloning a private repository (git-clone-from-URL
roadmap, phase 3 of 6, TBD-098). Pure logic only -- no file I/O, no process execution (see
the package docstring); phase 5 (job-system wiring) is where the returned env additions
actually reach a `git clone` subprocess.

Only `env:NAME` aliases are supported in this release -- `keychain:NAME` is accepted by the
shared `CredentialAlias` type's shape (TBD-058) but has no resolver anywhere in this
codebase yet (confirmed by inspection: `app.scanners.apisec.runner._resolve_secret`, the
only other place that resolves this alias shape today, also only ever handles `env:`).
Extending to a real OS keychain would need a new dependency (e.g. `keyring`, which itself
has no CLI-only, stdlib-only equivalent on Windows for *retrieving* a stored secret -- unlike
`security`/`secret-tool` on macOS/Linux) and is deliberately out of scope here rather than
built inconsistently across platforms; a `keychain:` alias resolves to `None`, exactly like
an unset `env:` variable, and the caller surfaces one clear message either way (see
`app.api...` phase 5 wiring).

The actual secret this resolves must NEVER reach argv, a log line, an evidence record, a
finding, or the job's own event stream (`ctx.emit("process_started", ..., argv=...)` logs
argv verbatim -- see `git_clone.py`'s own docstring). Confirmed directly on this machine: a
real `git clone`/`ls-remote` against a local HTTP server that challenges with `401` +
`WWW-Authenticate: Basic` correctly retries with the right `Authorization: Basic <...>`
header when `GIT_ASKPASS` is set to a helper that reads the secret from
`GIT_CREDENTIAL_ENV_VAR` and prints it to stdout on a "Password for ..." prompt (returning a
fixed, non-secret placeholder on a "Username for ..." prompt instead) -- the secret travels
only through that one environment variable, never through the helper's own argv (Git passes
the prompt text as the helper's argv, never the credential) and never through the main
`git clone` argv.

Git itself must receive `GIT_ASKPASS` as a real, already-installed executable path -- on
Windows, a bare `"<python> <script.py>"` string with a space was confirmed NOT to be split
into program+argument by this machine's Git for Windows (it was spawned as one literal,
nonexistent filename); a thin OS-native launcher resolves this, which needs a real file on
disk pointing at the currently-running interpreter. That file does not exist yet when a
clone starts, so writing it is phase 5's job (into the same per-job ephemeral work directory
as the clone destination), not this module's -- this module only supplies the fixed, OS-
independent *source* for the underlying Python helper and the one env var the secret itself
travels through.
"""

from __future__ import annotations

import os

#: The only env var the resolved secret is ever placed into; named distinctively so it is
#: never mistaken for a generic environment dump. Read by `ASKPASS_HELPER_SOURCE` below.
GIT_CREDENTIAL_ENV_VAR = "KAVACH_GIT_CREDENTIAL"

#: Non-secret: returned for a "Username for ..." prompt when a credential alias resolved.
#: Many providers (GitHub, GitLab) accept any non-empty placeholder as the username when the
#: real credential is supplied as the password; this is the same convention GitHub's own
#: docs recommend for PAT-over-HTTPS.
ASKPASS_USERNAME_PLACEHOLDER = "token"

#: The fixed source of the askpass helper Git invokes for each credential prompt. Confirmed
#: directly: Git passes the prompt text (e.g. "Username for '...': " or "Password for
#: '...': ") as this script's own argv[1], and reads the credential only from this script's
#: stdout -- never from its own argv, so the secret this prints is never visible in any
#: process listing or argv-logging the application itself does.
ASKPASS_HELPER_SOURCE = f"""\
import os
import sys

prompt = sys.argv[1] if len(sys.argv) > 1 else ""
if "username" in prompt.lower():
    sys.stdout.write({ASKPASS_USERNAME_PLACEHOLDER!r})
else:
    sys.stdout.write(os.environ.get({GIT_CREDENTIAL_ENV_VAR!r}, ""))
"""


def resolve_credential_alias(alias: str) -> str | None:
    """`env:NAME` resolves from this process's own environment; anything else (empty,
    `keychain:NAME`, or an `env:NAME` whose variable is unset) resolves to `None` -- the
    caller treats every `None` the same way (a clear "could not resolve" message), since
    silently falling back to an anonymous clone for a credential the operator explicitly
    configured would be a worse failure mode than refusing clearly."""
    if alias.startswith("env:"):
        return os.environ.get(alias[len("env:") :]) or None
    return None


def build_credential_env(secret: str | None) -> dict[str, str]:
    """The env additions a resolved secret contributes to the `git clone` subprocess's own
    environment -- never its argv. Empty when no secret resolved, so an anonymous clone's
    environment is completely unchanged by this module (relying only on phase 2's
    `GIT_CLONE_ENV` to fail cleanly if the repository actually needed one)."""
    if secret is None:
        return {}
    return {GIT_CREDENTIAL_ENV_VAR: secret}
