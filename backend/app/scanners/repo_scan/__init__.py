"""Repository Security Scanner (roadmap Phase 2) -- detection and self-test for each engine
live in app/integrations/ and app/services/integrations.py; this package holds the pure,
file-I/O-free argv/output-parsing logic for each engine's adapter, following the exact
same incremental approach used for the ZAP integration (app/scanners/zap_dast/). Nothing in
this package writes a file, creates a directory, or runs a process itself -- see
tests/test_static_guards.py::test_no_file_io_outside_storage.
"""
