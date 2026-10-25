"""Representative fixture bytes for every Phase 08 import adapter."""

from __future__ import annotations

import base64
import json

NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="db.internal.test"/></hostnames>
  <ports>
    <port protocol="tcp" portid="3306">
      <state state="open"/>
      <service name="mysql" product="MySQL" version="8.0.34" extrainfo="unauthorized"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.3"/>
    </port>
    <port protocol="udp" portid="53">
      <state state="open"/>
      <service name="domain"/>
    </port>
  </ports>
</host>
</nmaprun>
"""

NMAP_XML_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun version="7.94"><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>
"""

NESSUS_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2>
<Report><ReportHost name="10.0.0.9">
  <HostProperties>
    <tag name="host-ip">10.0.0.9</tag>
    <tag name="host-fqdn">app.internal.test</tag>
  </HostProperties>
  <ReportItem port="443" protocol="tcp" severity="3" pluginID="51192" pluginName="SSL Certificate Expiry">
    <risk_factor>High</risk_factor>
    <synopsis>The SSL certificate expires soon.</synopsis>
    <description>The X.509 certificate presented expires in 3 days.</description>
    <solution>Renew the certificate.</solution>
    <cve>CVE-2020-0001</cve>
    <xref>CWE:295</xref>
    <cvss_base_score>7.5</cvss_base_score>
  </ReportItem>
</ReportHost></Report></NessusClientData_v2>
"""

NUCLEI_JSONL = (
    json.dumps(
        {
            "template-id": "exposed-panel-jenkins",
            "matched-at": "http://10.0.0.7:8080/login",
            "host": "10.0.0.7:8080",
            "info": {
                "name": "Jenkins Login Panel Exposed",
                "severity": "medium",
                "description": "Jenkins login panel was detected.",
                "classification": {"cwe-id": ["CWE-200"], "cve-id": []},
                "reference": ["https://example.test/advisory"],
                "tags": ["panel", "jenkins"],
            },
        }
    )
    + "\n"
    + "not valid json\n"
    + json.dumps({"template-id": "", "info": {}})
    + "\n"
).encode("utf-8")

SARIF_JSON = json.dumps(
    {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurepowershell.net/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ExampleScanner",
                        "version": "1.2.3",
                        "rules": [
                            {
                                "id": "JS0001",
                                "shortDescription": {"text": "Use of eval()"},
                                "fullDescription": {
                                    "text": "eval() can execute arbitrary code (CWE-95)."
                                },
                                "properties": {"tags": ["security", "CWE-95"]},
                                "helpUri": "https://example.test/rules/JS0001",
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "JS0001",
                        "level": "error",
                        "message": {"text": "eval() used with untrusted input"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.js"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
).encode("utf-8")

GENERIC_CSV = (
    b"Vulnerability Name,Risk,Host,Solution\r\n"
    b"Outdated jQuery,Medium,10.0.0.3,Upgrade jQuery to the latest version\r\n"
    b",High,10.0.0.4,Missing title should be rejected\r\n"
)

GENERIC_CSV_NESSUS_STYLE = (
    b"Plugin ID,CVE,CVSS,Risk,Host,Name,Synopsis,Description,Solution\r\n"
    b"12345,CVE-2021-9999,7.5,High,10.0.0.9,Outdated OpenSSL,Outdated crypto library,"
    b"A vulnerable version of OpenSSL is in use.,Upgrade OpenSSL\r\n"
)

GENERIC_JSON = json.dumps(
    {
        "findings": [
            {
                "title": "Reflected XSS",
                "severity": "high",
                "host": "10.0.0.6",
                "url": "http://10.0.0.6/search?q=1",
                "parameter": "q",
                "cwe": "CWE-79",
                "summary": "Unsanitized input reflected in response.",
            },
            {"severity": "low"},  # no title -> rejected
        ]
    }
).encode("utf-8")

PDF_MINIMAL = base64.b64decode(
    "JVBERi0xLjMKJeLjz9MKMSAwIG9iago8PAovUHJvZHVjZXIgKHB5cGRmKQo+PgplbmRvYmoKMiAwIG9iago8PAovVHlwZSAvUGFnZXMKL0NvdW50IDEKL0tpZHMgWyA0IDAgUiBdCj4+CmVuZG9iagozIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAyIDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovVHlwZSAvUGFnZQovUmVzb3VyY2VzIDw8Ci9Gb250IDw8Ci9GMSA1IDAgUgo+Pgo+PgovTWVkaWFCb3ggWyAwLjAgMC4wIDMwMCAxNTAgXQovUGFyZW50IDIgMCBSCi9Db250ZW50cyA2IDAgUgo+PgplbmRvYmoKNSAwIG9iago8PAovVHlwZSAvRm9udAovU3VidHlwZSAvVHlwZTEKL0Jhc2VGb250IC9IZWx2ZXRpY2EKPj4KZW5kb2JqCjYgMCBvYmoKPDwKL0xlbmd0aCA3MQo+PgpzdHJlYW0KQlQgL0YxIDE4IFRmIDIwIDEwMCBUZCAoU2FtcGxlIFZBUFQgZmluZGluZyB0ZXh0IGV4dHJhY3Rpb24gdGVzdCkgVGogRVQKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNwowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDA1NCAwMDAwMCBuIAowMDAwMDAwMTEzIDAwMDAwIG4gCjAwMDAwMDAxNjIgMDAwMDAgbiAKMDAwMDAwMDI5NCAwMDAwMCBuIAowMDAwMDAwMzY0IDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgNwovUm9vdCAzIDAgUgovSW5mbyAxIDAgUgo+PgpzdGFydHhyZWYKNDg1CiUlRU9GCg=="
)
