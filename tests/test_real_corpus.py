"""Regression tests on tool definitions captured from real MCP servers.

The corpus (``tests/fixtures/real``, see its README) holds 15 popular open-source
servers. Every finding they produce was triaged by hand; the expected set below
is exact so that a rule change that adds noise or loses a true positive fails here.
"""

from collections import Counter
from pathlib import Path

import pytest

from mcp_scanner.engine import analyze
from mcp_scanner.manifest import load_manifest

REAL = Path(__file__).parent / "fixtures" / "real"
SERVERS = sorted(path.stem for path in REAL.glob("*.json"))

# Text rules that look for hidden instructions or characters: real servers must not trigger them.
POISONING_RULES = {f"MCPS{n}" for n in (*range(101, 110), 120, 121, 122)}

# Genuinely high-impact capabilities (exec, destructive) and risky parameters.
EXPECTED_CAPABILITIES = {
    ("MCPS211", "desktop-commander/force_terminate"),
    ("MCPS211", "desktop-commander/kill_process"),
    ("MCPS211", "desktop-commander/start_process"),
    ("MCPS211", "github/delete_file"),
    ("MCPS211", "grafana/delete_annotation"),
    ("MCPS211", "grafana/delete_snapshot"),
    ("MCPS211", "kubernetes/exec_in_pod"),
    ("MCPS211", "kubernetes/kubectl_delete"),
    ("MCPS211", "kubernetes/kubectl_generic"),
    ("MCPS211", "kubernetes/uninstall_helm_chart"),
    ("MCPS211", "memory/delete_entities"),
    ("MCPS211", "memory/delete_observations"),
    ("MCPS211", "memory/delete_relations"),
    ("MCPS211", "notion/API-delete-a-block"),
    ("MCPS211", "playwright/browser_run_code_unsafe"),
    ("MCPS211", "supabase/delete_branch"),
    ("MCPS211", "supabase/execute_sql"),
    # Saves a PDF file to disk while declaring readOnlyHint=true.
    ("MCPS212", "playwright/browser_pdf_save"),
    ("MCPS213", "desktop-commander/start_process"),
    ("MCPS213", "kubernetes/kubectl_generic"),
    ("MCPS213", "playwright/browser_run_code_unsafe"),
    ("MCPS213", "supabase/apply_migration"),
    ("MCPS213", "supabase/execute_sql"),
    ("MCPS213", "supabase/query_logs"),
}
# Tool names exposed by two servers: accurate, but harmless in clients that namespace tools.
SHARED_NAMES = {
    "desktop-commander": [
        "create_directory",
        "get_file_info",
        "list_directory",
        "move_file",
        "read_file",
        "read_multiple_files",
        "write_file",
    ],
    "github": ["create_branch", "list_branches"],
}
COUNTERPARTS = {"desktop-commander": "filesystem", "github": "supabase"}
EXPECTED_SHARED = {
    ("MCPS106", f"{server}/{name}")
    for first, names in SHARED_NAMES.items()
    for server in (first, COUNTERPARTS[first])
    for name in names
}
# The only long description (6302 characters): a usage guide, low severity.
EXPECTED_OTHER = {("MCPS110", "desktop-commander/start_search")}


def _load(*names: str):
    inventories = []
    for name in names:
        loaded, notices = load_manifest(str(REAL / f"{name}.json"))
        assert notices == []
        inventories.extend(loaded)
    return inventories


@pytest.fixture(scope="module")
def corpus_findings():
    return analyze([], _load(*SERVERS))


def test_corpus_is_complete():
    inventories = _load(*SERVERS)
    assert len(inventories) == 15
    assert sum(len(inv.tools) for inv in inventories) == 372


@pytest.mark.parametrize("server", SERVERS)
def test_no_poisoning_or_unicode_findings(server):
    findings = analyze([], _load(server))
    assert [(f.rule.id, f.message) for f in findings if f.rule.id in POISONING_RULES] == []


@pytest.mark.parametrize("server", SERVERS)
def test_each_server_alone_has_only_expected_findings(server):
    found = {(f.rule.id, f.target) for f in analyze([], _load(server))}
    expected = EXPECTED_CAPABILITIES | EXPECTED_OTHER
    assert found == {item for item in expected if item[1].startswith(f"{server}/")}


def test_together_only_tool_name_clashes_are_added(corpus_findings):
    cross = [f for f in corpus_findings if f.rule.id == "MCPS106"]
    assert cross and all("is also exposed by server(s)" in f.message for f in cross)


def test_findings_match_the_triaged_set(corpus_findings):
    found = Counter((f.rule.id, f.target) for f in corpus_findings)
    assert all(count == 1 for count in found.values())
    assert set(found) == EXPECTED_CAPABILITIES | EXPECTED_SHARED | EXPECTED_OTHER
