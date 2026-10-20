"""Job-system self-test runner (module `self_test`).

It exercises every job-system path (stages, progress, counters, warnings, budgets,
cancellation, output files, subprocess timeout/kill) WITHOUT any network activity:
targets are only scope-checked and counted against the rate/request budgets.

Exposed only when VAPT_ENABLE_SELFTEST_JOBS=1 so production builds never show
synthetic progress. It produces no findings.
"""

from __future__ import annotations

import json
import sys

from app.jobs.context import JobContext, RunResult
from app.scope.canonical import normalize_target

LIMITS = {
    "steps": (1, 50, 5),
    "step_seconds": (0.0, 5.0, 0.2),
    "fail_at_step": (0, 50, 0),
    "warn_at_step": (0, 50, 0),
    "process_seconds": (0.0, 60.0, 0.0),
    "process_timeout": (0.5, 60.0, 30.0),
}


def _param(ctx: JobContext, name: str) -> float:
    low, high, default = LIMITS[name]
    raw = ctx.scan.parameters.get(name, default)
    try:
        value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        value = float(default)
    return max(float(low), min(float(high), value))


class SelfTestRunner:
    name = "Job system self-test (no network traffic)"

    def run(self, ctx: JobContext) -> RunResult:
        steps = int(_param(ctx, "steps"))
        step_seconds = _param(ctx, "step_seconds")
        fail_at = int(_param(ctx, "fail_at_step"))
        warn_at = int(_param(ctx, "warn_at_step"))
        hosts = sorted({normalize_target(t).host for t in ctx.scan.authorized_targets})
        ctx.stage("prepare", 0.0)
        ctx.emit(
            "note", "self-test: no requests are sent; targets are only scope-checked and budgeted"
        )
        for host in hosts:
            ctx.incr("targets")
            ctx.emit("target", f"target {host} admitted by scope policy")
        ctx.stage("simulate", 0.0)
        for step in range(1, steps + 1):
            ctx.checkpoint()
            for host in hosts:
                ctx.acquire_request(host)  # exercises the budget; nothing is sent
                ctx.incr("simulated_requests")
            ctx.sleep(step_seconds)
            ctx.incr("steps_done")
            ctx.set_percent(round(step * 100.0 / steps, 1))
            if step == warn_at:
                ctx.warn(f"self-test warning requested at step {step}")
            if step == fail_at:
                ctx.error(f"self-test failure requested at step {step}")
                return RunResult(failed=True)
        if _param(ctx, "process_seconds") > 0:
            ctx.stage("subprocess")
            code = f"import time; time.sleep({_param(ctx, 'process_seconds')})"
            result = ctx.run_process(
                [sys.executable, "-c", code],
                allowed_executables=[sys.executable],
                timeout=_param(ctx, "process_timeout"),
            )
            if result.timed_out:
                ctx.warn(
                    "self-test subprocess timed out after "
                    f"{result.duration_seconds}s and was killed"
                )
        ctx.stage("report", 100.0)
        summary = {"steps": steps, "targets": hosts, "network_requests_sent": 0}
        ctx.write_output("selftest-summary.json", json.dumps(summary, indent=2).encode())
        return RunResult()
