"""Property-based tests of the reports: SARIF always validates, every format renders."""

import json
from pathlib import Path

import jsonschema
from hypothesis import given
from hypothesis import strategies as st

from fuzzing import UNICODE_TEXT, provider_tokens
from mcp_scanner.models import Finding, Location, Notice, Severity
from mcp_scanner.reporters import json_report, sarif, table
from mcp_scanner.rules.catalog import all_rules
from mcp_scanner.scanner import ScanReport

SCHEMA = json.loads(
    (Path(__file__).parent / "schemas" / "sarif-2.1.0.json").read_text(encoding="utf-8")
)
VALIDATOR = jsonschema.Draft7Validator(SCHEMA)
ROOT = Path(__file__).resolve().parent.parent

TEXT = UNICODE_TEXT | provider_tokens.map(lambda labelled: f"key {labelled[1]} here")
OPTIONAL_TEXT = st.none() | TEXT
PATHS = (
    st.none()
    | st.sampled_from(
        [
            str(ROOT / "tests" / "fixtures" / "configs" / "insecure.json"),
            str(ROOT / "a dir" / "100% [x] #1.json"),
            "relative/config.json",
            str(Path(ROOT.anchor) / "elsewhere" / "mcp.json"),
        ]
    )
    | UNICODE_TEXT.filter(lambda text: text.strip() and "\x00" not in text)
)
LOCATIONS = st.builds(
    Location,
    path=PATHS,
    line=st.none() | st.integers(1, 10**6),
    column=st.none() | st.integers(1, 10**4),
    pointer=st.text(max_size=20),
)
FINDINGS = st.builds(
    Finding,
    rule=st.sampled_from(all_rules()),
    message=TEXT,
    location=LOCATIONS,
    server=OPTIONAL_TEXT,
    tool=OPTIONAL_TEXT,
    field=OPTIONAL_TEXT,
    evidence=OPTIONAL_TEXT,
    severity=st.none() | st.sampled_from(Severity),
    prompt=OPTIONAL_TEXT,
    resource=OPTIONAL_TEXT,
)
NOTICES = st.builds(
    Notice, level=st.sampled_from(["error", "warning", "note"]), message=TEXT, path=PATHS
)
REPORTS = st.builds(
    ScanReport,
    findings=st.lists(FINDINGS, max_size=6),
    servers=st.just([]),
    inventories=st.just([]),
    documents=st.just([]),
    notices=st.lists(NOTICES, max_size=3),
    pins=st.none(),
    started_at=st.just("2026-01-01T00:00:00+00:00"),
    finished_at=st.just("2026-01-01T00:00:01+00:00"),
)


@given(REPORTS, st.sampled_from(Severity))
def test_sarif_always_validates(report, min_severity):
    payload = sarif.build(report, root=ROOT, min_severity=min_severity)
    errors = sorted(VALIDATOR.iter_errors(payload), key=str)
    assert not errors, errors[0].message
    rendered = json.loads(sarif.render(report, root=ROOT, min_severity=min_severity))
    assert rendered["runs"][0]["results"] == json.loads(json.dumps(payload))["runs"][0]["results"]


@given(REPORTS)
def test_every_format_renders(report):
    json.loads(json_report.render(report, root=ROOT))
    for color in (False, True):
        output = table.render(report, color=color, width=100, root=ROOT)
        assert output.endswith("\n")


def test_undecodable_file_names_still_give_valid_sarif():
    # Found by fuzzing: a lone surrogate in a path, which stands for an undecodable file
    # name byte (surrogateescape on POSIX), made quote() and Path.as_uri() raise.
    name = "config-" + chr(0xDCFF) + ".json"
    location = Location(str(ROOT / name), 3, 1)
    report = ScanReport(
        findings=[
            Finding(all_rules()[0], "m", location),
            Finding(all_rules()[0], "n", Location(name)),
        ],
        servers=[],
        inventories=[],
        documents=[],
        notices=[Notice("error", "cannot parse", str(Path(ROOT.anchor) / name))],
        pins=None,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
    )
    payload = sarif.build(report, root=ROOT)
    assert not list(VALIDATOR.iter_errors(payload))
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in payload["runs"][0]["results"]
    ]
    assert all("config-%EF%BF%BD.json" in uri for uri in uris)
