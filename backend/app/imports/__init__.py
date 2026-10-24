"""Import Center — external VAPT report ingestion (MASTER_SPEC Module 8, Option D).

Untrusted file content is parsed, never executed: no shelling out, no `eval`/`exec`, no
unsafe YAML/XML/pickle loaders, and uploaded bytes are stored opaquely (`raw.bin`) and
never placed on a path that is later opened by a shell or interpreter.
"""
