"""Container image vulnerability scanner (module `container_image`, security/reliability/
scope roadmap Phase 3, TBD-110). Scans an operator-specified image reference that is
already present on the local Docker daemon -- never a remote registry pull triggered by
this application; see `runner.py`'s own module docstring."""
