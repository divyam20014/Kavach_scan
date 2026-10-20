"""Surface rules (`vapt-surface-rules` 1.0.0), registered in the shared rule registry.

Discovery itself is never a vulnerability: discovered hosts, IPs, open ports and web
origins are inventory (assets + observations). Only *exposure facts* with a security
implication become findings, and they say what was observed, not what might be exploitable.
"""

from __future__ import annotations

from app.models.common import Confidence, Severity
from app.scanners.webapp.rules import Kind, Rule, register_rules

CATALOG_ID = "vapt-surface-rules"
CATALOG_VERSION = "1.0.0"

SURFACE_RULES = [
    Rule(
        "SURF-SVC-001",
        "Database or cache service reachable",
        "exposure",
        Kind.PROBE,
        Severity.MEDIUM,
        Confidence.CONFIRMED,
        (284,),
        "A02",
        "A TCP connection to a common database/cache port succeeded from the scanning host. "
        "Reachability was observed; no login or query was attempted.",
        "Restrict the service to trusted networks (firewall/security group) unless exposure "
        "is intended and protected.",
        (),
        aggregate=False,
    ),
    Rule(
        "SURF-SVC-002",
        "Remote administration service reachable",
        "exposure",
        Kind.PROBE,
        Severity.LOW,
        Confidence.CONFIRMED,
        (284,),
        "A02",
        "A remote administration port (SSH, RDP, VNC, WinRM, SMB) accepted a TCP connection. "
        "No authentication was attempted.",
        "Expose remote administration only via VPN/bastion or an IP allowlist.",
        (),
        aggregate=False,
    ),
    Rule(
        "SURF-SVC-003",
        "Cleartext protocol service reachable",
        "exposure",
        Kind.PROBE,
        Severity.LOW,
        Confidence.CONFIRMED,
        (319,),
        "A04",
        "A service that normally transmits credentials in cleartext (FTP, Telnet) is reachable.",
        "Disable the service or replace it with an encrypted alternative.",
        (),
        aggregate=False,
    ),
    Rule(
        "SURF-BANNER-001",
        "Service banner discloses product version",
        "information-disclosure",
        Kind.PROBE,
        Severity.INFORMATIONAL,
        Confidence.CONFIRMED,
        (200,),
        "A02",
        "The service's own greeting (read passively, nothing sent) includes a product "
        "version. Observation that helps attackers match known issues; not proof of one.",
        "Reduce banner detail where the software allows it.",
        (),
        aggregate=False,
    ),
    Rule(
        "SURF-COV-001",
        "Port coverage",
        "coverage",
        Kind.PROBE,
        Severity.INFORMATIONAL,
        Confidence.CONFIRMED,
        (),
        "",
        "Which ports were tested on which hosts, and which were not (with reasons).",
        "",
        (),
    ),
    Rule(
        "SURF-SRC-001",
        "Passive source query",
        "coverage",
        Kind.TOOL,
        Severity.INFORMATIONAL,
        Confidence.CONFIRMED,
        (),
        "",
        "Third-party passive source used for candidate collection (disclosed).",
        "",
        (),
    ),
]
register_rules(SURFACE_RULES)

DATABASE_PORTS = {
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}
ADMIN_PORTS = {22: "ssh", 3389: "rdp", 5900: "vnc", 5985: "winrm", 5986: "winrm-https", 445: "smb"}
CLEARTEXT_PORTS = {21: "ftp", 23: "telnet"}
