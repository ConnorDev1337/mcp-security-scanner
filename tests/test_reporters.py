import json
import random
import string
from pathlib import Path

import jsonschema
import pytest

from mcp_scanner.models import Severity
from mcp_scanner.reporters import json_report, sarif, table
from mcp_scanner.rules.catalog import all_rules
from mcp_scanner.rules.secrets import mask, mask_args
from mcp_scanner.scanner import ScanOptions, run_scan

SCHEMA = json.loads(
    (Path(__file__).parent / "schemas" / "sarif-2.1.0.json").read_text(encoding="utf-8")
)
TOKEN = "ghp_" + "".join(random.Random(7).choices(string.ascii_letters + string.digits, k=36))


@pytest.fixture
def report(fixtures, write_json):
    secret_cfg = write_json(
        "secret.json",
        {
            "mcpServers": {
                "leaky": {
                    "command": "npx",
                    "args": ["-y", "leaky-mcp@1.0.0", "--token", TOKEN],
                    "env": {"GITHUB_TOKEN": TOKEN},
                }
            }
        },
    )
    options = ScanOptions(
        configs=[str(fixtures / "configs" / "insecure.json"), str(secret_cfg)],
        tool_manifests=[str(fixtures / "tools" / "poisoned.json")],
    )
    return run_scan(options)


def test_sarif_is_valid_against_official_schema(report, fixtures):
    payload = sarif.build(report, root=fixtures.parent.parent)
    jsonschema.validate(payload, SCHEMA)
    run = payload["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == len(all_rules())
    assert len(run["results"]) == len(report.findings)
    for rule in run["tool"]["driver"]["rules"]:
        assert 0 < float(rule["properties"]["security-severity"]) <= 10


def test_sarif_locations_are_repo_relative(report, fixtures):
    root = fixtures.parent.parent
    run = sarif.build(report, root=root)["runs"][0]
    result = next(r for r in run["results"] if r["ruleId"] == "MCPS213")
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"] == {
        "uri": "tests/fixtures/tools/poisoned.json",
        "uriBaseId": "%SRCROOT%",
    }
    assert physical["region"]["startLine"] == 55
    assert result["level"] == "warning"
    assert result["partialFingerprints"]["mcpScanner/v1"]
    critical = next(r for r in run["results"] if r["properties"]["severity"] == "critical")
    assert critical["level"] == "error"


def test_sarif_paths_outside_root_use_file_uris(report, tmp_path):
    run = sarif.build(report, root=tmp_path / "elsewhere")["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("file:///")


@pytest.mark.parametrize("renderer", [sarif.render, json_report.render, table.render])
def test_no_output_format_leaks_secrets(report, renderer):
    output = renderer(report)
    assert TOKEN not in output
    assert "S3cr3t-Pa55w0rd!" not in output
    assert "hunter2pass" not in output
    assert "9f8e7d6c5b4a39281706f5e4d3c2b1a0" not in output


def test_json_report_structure(report):
    payload = json.loads(json_report.render(report))
    assert payload["schema"] == "mcp-security-scanner/report/v1"
    summary = payload["summary"]
    assert summary["findings"] == len(payload["findings"]) == len(report.findings)
    assert sum(summary["by_severity"].values()) == summary["findings"]
    assert summary["manifest_only_servers"] == ["evil-math", "mailer"]
    leaky = next(s for s in payload["servers"] if s["name"] == "leaky")
    assert leaky["env_keys"] == ["GITHUB_TOKEN"]
    assert leaky["args"][-1] == "ghp_****(40 chars)"
    first = payload["findings"][0]
    assert {"rule_id", "severity", "message", "location", "remediation", "fingerprint"} <= set(
        first
    )


def test_min_severity_filters_every_format(report):
    payload = json.loads(json_report.render(report, min_severity=Severity.CRITICAL))
    assert {f["severity"] for f in payload["findings"]} == {"critical"}
    run = sarif.build(report, min_severity=Severity.CRITICAL)["runs"][0]
    assert {r["level"] for r in run["results"]} == {"error"}
    text = table.render(report, min_severity=Severity.CRITICAL, width=100)
    assert "below --min-severity critical not shown" in text


def test_table_is_ascii_safe_and_respects_width(report):
    text = table.render(report, width=100)
    widths = {len(line) for line in text.splitlines() if line.startswith(("+", "|"))}
    assert widths == {100}
    assert "\x1b" not in text
    colored = table.render(report, width=100, color=True)
    assert "\x1b[1;97;41mCRITICAL" in colored


def test_table_escapes_hostile_text(write_json):
    path = write_json(
        "tools.json",
        {"tools": [{"name": "x", "description": "Hi \x1b[2J\x1b[8mhidden ‮ text"}]},
    )
    text = table.render(run_scan(ScanOptions(tool_manifests=[str(path)])), width=120)
    assert "\x1b" not in text and "‮" not in text
    assert "U+001B" in text and "U+202E" in text


def test_empty_report(write_json):
    path = write_json("empty.json", {"mcpServers": {}})
    text = table.render(run_scan(ScanOptions(configs=[str(path)])))
    assert "No findings." in text and "Findings: none." in text


def test_mask_helpers():
    assert mask(f"token {TOKEN} end") == "token ghp_****(40 chars) end"
    assert mask("postgres://u:pa55word@h/db?sslmode=require&password=x1y2z3") == (
        "postgres://u:****@h/db?sslmode=require&password=****"
    )
    args = ["--api-key", "abcdef1234567", "--token=${T}", "A_SECRET=short", "-v"]
    assert mask_args(args) == [
        "--api-key",
        "abcd****(13 chars)",
        "--token=${T}",
        "A_SECRET=****",
        "-v",
    ]
