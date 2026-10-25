"""ZAP Automation-Framework-driven scanning (roadmap Phase 1, TBD-079/080).

Increment 1 (TBD-079): detection and self-test only (`app/integrations/zap.py`).
Increment 2 (this package, TBD-080): the pure, file-I/O-free building blocks for a real
scan -- Automation Framework plan generation, argv construction/validation, and report
parsing -- each proven directly against a real local ZAP 2.17.0 installation. Nothing in
this package writes a file, creates a directory, or runs a process itself: every module
in this project that touches the filesystem does so through `app/storage/`
(`tests/test_static_guards.py::test_no_file_io_outside_storage`), so the orchestration that
actually writes the plan, runs the process, and reads the report back is job-system wiring
for a later increment, not this one.
"""
