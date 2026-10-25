"""ZAP Automation Framework plan/argv building (roadmap Phase 1 increment 2, TBD-080).

Pure, file-I/O-free logic only -- nothing here writes a file or runs a process. The exact
job types and YAML shape asserted below were confirmed directly against a real local ZAP
2.17.0 run (see TBD-080): a plan with this shape printed "Automation plan succeeded!" and
produced a real `traditional-json` report.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.scanners.zap_dast.plan import (
    CONTEXT_NAME,
    REPORT_FILE_NAME,
    ZapPlanError,
    baseline_argv,
    build_baseline_plan,
    validate_argv,
)


def test_baseline_plan_has_the_confirmed_working_job_shape(tmp_path: Path) -> None:
    text = build_baseline_plan(["http://127.0.0.1:18080/"], tmp_path / "report")
    plan = yaml.safe_load(text)
    assert plan["env"]["contexts"][0]["name"] == CONTEXT_NAME
    assert plan["env"]["contexts"][0]["urls"] == ["http://127.0.0.1:18080/"]
    assert plan["env"]["parameters"]["failOnError"] is True
    job_types = [j["type"] for j in plan["jobs"]]
    assert job_types == ["spider", "passiveScan-wait", "report"]
    report_job = plan["jobs"][-1]["parameters"]
    assert report_job["template"] == "traditional-json"
    assert report_job["reportFile"] + ".json" == REPORT_FILE_NAME
    # never an active-scan job in this increment
    assert "activeScan" not in job_types


def test_baseline_plan_adds_one_spider_job_per_target(tmp_path: Path) -> None:
    targets = ["http://a.example/", "http://b.example/"]
    plan = yaml.safe_load(build_baseline_plan(targets, tmp_path))
    spider_urls = [j["parameters"]["url"] for j in plan["jobs"] if j["type"] == "spider"]
    assert spider_urls == targets
    assert sorted(plan["env"]["contexts"][0]["includePaths"]) == sorted(
        [r"http://a\.example.*", r"http://b\.example.*"]
    )


def test_include_path_pattern_is_escaped_not_raw_interpolated(tmp_path: Path) -> None:
    # A target carrying regex metacharacters must never widen the include pattern.
    plan = yaml.safe_load(build_baseline_plan(["http://a.example/"], tmp_path))
    pattern = plan["env"]["contexts"][0]["includePaths"][0]
    assert pattern.startswith(r"http://a\.example")


@pytest.mark.parametrize(
    ("targets", "fragment"),
    [
        ([], "at least one target"),
        (["not-a-url"], "must be an absolute http"),
        (["ftp://a.example/"], "must be an absolute http"),
        ([f"http://t{i}.example/" for i in range(11)], "at most 10 targets"),
    ],
)
def test_plan_rejects_invalid_targets(tmp_path: Path, targets: list[str], fragment: str) -> None:
    with pytest.raises(ZapPlanError, match=fragment):
        build_baseline_plan(targets, tmp_path)


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"spider_max_minutes": 0}, "spider_max_minutes"),
        ({"spider_max_minutes": 999}, "spider_max_minutes"),
        ({"passive_max_minutes": 0}, "passive_max_minutes"),
    ],
)
def test_plan_rejects_out_of_range_durations(
    tmp_path: Path, kwargs: dict[str, int], fragment: str
) -> None:
    with pytest.raises(ZapPlanError, match=fragment):
        build_baseline_plan(["http://a.example/"], tmp_path, **kwargs)  # type: ignore[arg-type]


def test_baseline_argv_matches_the_confirmed_working_invocation(tmp_path: Path) -> None:
    argv = baseline_argv(
        "/usr/bin/java", "/opt/zap/zap-2.17.0.jar", tmp_path / "plan.yaml", tmp_path / "home"
    )
    assert argv == [
        "/usr/bin/java",
        "-jar",
        "/opt/zap/zap-2.17.0.jar",
        "-cmd",
        "-autorun",
        str(tmp_path / "plan.yaml"),
        "-dir",
        str(tmp_path / "home"),
        "-silent",
    ]


def test_validate_argv_rejects_every_unsafe_flag() -> None:
    base = ["/usr/bin/java", "-jar", "/opt/zap/zap.jar"]
    for unsafe in (
        ["-daemon"],
        ["-port", "8090"],
        ["-host", "0.0.0.0"],  # noqa: S104 - asserted to be refused, never bound
        ["-config", "api.key=x"],
        ["-newsession", "s"],
    ):
        with pytest.raises(ZapPlanError, match="unsafe or unrecognized"):
            validate_argv([*base, *unsafe])


@pytest.mark.parametrize(
    "argv",
    [
        ["/usr/bin/java", "-jar", "/opt/zap/zap.jar", "-cmd"],  # missing -autorun/-dir
        ["/usr/bin/java", "-jar", "/opt/zap/zap.jar", "-cmd", "-autorun"],  # missing value
        ["/usr/bin/java", "/opt/zap/zap.jar", "-cmd"],  # missing -jar
    ],
)
def test_validate_argv_rejects_incomplete_or_malformed_argv(argv: list[str]) -> None:
    with pytest.raises(ZapPlanError):
        validate_argv(argv)


def test_validate_argv_accepts_the_confirmed_working_shape(tmp_path: Path) -> None:
    validate_argv(
        baseline_argv("/usr/bin/java", "/opt/zap/zap.jar", tmp_path / "p", tmp_path / "h")
    )
