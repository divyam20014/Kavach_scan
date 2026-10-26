"""Pure argv builder and URL validation for cloning a repository from an operator-supplied
URL (git-clone-from-URL roadmap, phase 2 of 6, TBD-097). Pure logic -- no file I/O, no
process execution (see the package docstring). No credential handling yet (phase 3) and no
job-system wiring yet (phase 5): this module only builds a safe, bounded `git clone` argv
for a public (or already-reachable) HTTPS repository.

Every flag and the scheme restriction below were confirmed directly against real `git
clone` invocations on this machine against a tiny, well-known public test repository
(`https://github.com/octocat/Hello-World.git`, GitHub's own demo repo, not a scan target),
not assumed from documentation. Three real, safety-relevant discoveries:

1. **Git supports transport schemes far beyond `http(s)://`, several of which are a real
   command-execution or local-file-disclosure risk.** `ext::<command>` is a legitimate Git
   "transport helper" that runs an arbitrary shell command as the clone's own transport --
   confirmed directly that a current Git install (2.50.1) already refuses this by its own
   `protocol.ext.allow=never` default (`fatal: transport 'ext' not allowed`), but that
   default is a property of the *installed Git version/config*, never something this
   application can assume is true on every machine it runs on. `file://` is still accepted
   by a current, default-configured Git install -- confirmed directly -- which would let a
   "clone" copy an arbitrary local directory the application can read. Both are closed by
   construction here: `validate_https_url` accepts only `https://`, never relying on Git's
   own defaults alone.
2. **A repository that requires authentication Git has no credential for would otherwise
   prompt interactively on stdin and hang indefinitely** in a non-interactive subprocess --
   `GIT_TERMINAL_PROMPT=0` is Git's own documented switch for exactly this ("never prompt,
   fail immediately instead"); confirmed directly that a real inaccessible-repository clone
   attempt fails cleanly and quickly (in seconds) with this set, not assumed. This is an
   environment variable, not an argv flag, and must always accompany any argv this module
   builds (`GIT_CLONE_ENV`) -- callers pass it via `run_process`'s own `extra_env`.
3. **GitHub's own HTTPS clone genuinely supports a bounded, shallow, partial clone**:
   `--depth 1 --single-branch --no-tags --filter=blob:limit=<n>` was run for real and
   produced a genuinely shallow repository (`git rev-parse --is-shallow-repository` ->
   `true`, exactly one commit of history) -- confirmed directly, not assumed to work the
   same way every native adapter's own bounded flags already do.
4. **On Windows, a clone destination nested under this application's own real data
   directory (`projects/<32-hex id>/scans/<32-hex id>/work/...`) can exceed the default
   260-character path limit for Git's own internal object paths**, confirmed directly: a
   real clone of this module's own test repository into a path of this exact shape failed
   with `error: unable to open loose object ...: Filename too long`, even though the
   destination path itself was far under the limit -- the failure comes from a *git
   object's own path inside `.git/objects/`*, not the destination path this module
   receives. `-c core.longpaths=true` (passed before `clone`, confirmed directly to fix the
   identical failure) is Git for Windows' own documented switch for this; it is always
   included, never conditional on the host OS, since it is a no-op (not an error) on
   Git versions/platforms that do not need it.



Credential handling (phase 3) will never put a secret into the argv this module builds --
any argv is written verbatim into the job's own event log (`ctx.emit("process_started", ...,
argv=...)`, confirmed by reading `app/jobs/context.py::run_process`), so a secret belongs
only in an environment variable a future phase supplies separately, never here.
"""

from __future__ import annotations

import re
from pathlib import Path

MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 1800
MIN_MAX_BLOB_BYTES = 1024
MAX_MAX_BLOB_BYTES = 200 * 1024 * 1024

#: Only `https://` is ever accepted -- see the module docstring's discovery (1). No
#: credentials, no whitespace; mirrors `app.models.project._http_url`'s own shape but kept
#: local to this module since repository-URL validation is a repo_scan-specific concern.
_HTTPS_URL_RE = re.compile(r"^https://[^\s/@]+(/[^\s]*)?$", re.IGNORECASE)

#: Always passed as `extra_env` alongside any argv this module builds -- see discovery (2).
GIT_CLONE_ENV: dict[str, str] = {"GIT_TERMINAL_PROMPT": "0"}


class GitCloneArgvError(ValueError):
    """The argv would be unsafe or invalid; nothing is executed."""


def validate_https_url(url: str) -> None:
    if not _HTTPS_URL_RE.match(url):
        raise GitCloneArgvError(
            "repository URL must be a plain https:// URL, without embedded credentials or "
            "whitespace -- no other transport (git://, ssh://, file://, ext::, ...) is ever "
            "allowed"
        )


def build_clone_argv(
    git_executable: str,
    url: str,
    dest_dir: Path,
    *,
    timeout_seconds: int = 300,
    max_blob_bytes: int = 50 * 1024 * 1024,
) -> list[str]:
    """`git clone --depth 1 --single-branch --no-tags --filter=blob:limit=<n> <url>
    <dest_dir>`. `dest_dir` must not already exist or must be empty -- Git's own clone
    refuses otherwise; this is a runtime precondition for the caller to ensure, not
    something this pure argv builder can check. `timeout_seconds` bounds the subprocess
    itself (enforced by the caller's own process wrapper, not a `git` flag); a repository
    whose shallow, blob-size-limited clone still cannot finish in time fails cleanly via
    that timeout rather than this module inventing its own total-size accounting."""
    validate_https_url(url)
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise GitCloneArgvError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
        )
    if not MIN_MAX_BLOB_BYTES <= max_blob_bytes <= MAX_MAX_BLOB_BYTES:
        raise GitCloneArgvError(
            f"max_blob_bytes must be between {MIN_MAX_BLOB_BYTES} and {MAX_MAX_BLOB_BYTES}"
        )
    return [
        git_executable,
        "-c",
        "core.longpaths=true",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        f"--filter=blob:limit={max_blob_bytes}",
        url,
        str(dest_dir),
    ]
