"""Regression tests on definitions captured from real MCP servers.

The corpus (``tests/fixtures/real``, see its README) holds 23 popular open-source
servers: their tools, server instructions, prompts, resources and resource
templates. Every finding they produce was triaged by hand; the expected set below
is exact so that a rule change that adds noise or loses a true positive fails here.
"""

from collections import Counter
from pathlib import Path

import pytest

from mcp_scanner.engine import analyze
from mcp_scanner.manifest import load_manifest
from mcp_scanner.models import ResourceDefinition
from mcp_scanner.pinning import PinStore, check_pins

REAL = Path(__file__).parent / "fixtures" / "real"
SERVERS = sorted(path.stem for path in REAL.glob("*.json"))

# Tools, prompts, resources and resource templates listed by each server.
COUNTS = {
    "context7": (2, 0, 0, 0),
    "desktop-commander": (25, 0, 2, 0),
    "everything": (13, 4, 7, 2),
    "fetch": (1, 1, 0, 0),
    "filesystem": (14, 0, 0, 0),
    "git": (12, 0, 0, 0),
    "git-cyanheads": (28, 1, 1, 1),
    "github": (91, 2, 4, 5),
    "grafana": (79, 0, 2, 0),
    "heroku": (33, 0, 1, 0),
    "kubernetes": (23, 1, 5, 0),
    "memory": (9, 0, 1, 0),
    "mongodb": (27, 0, 2, 1),
    "notion": (24, 0, 0, 0),
    "playwright": (45, 0, 0, 0),
    "playwright-ea": (33, 0, 1, 0),
    "puppeteer": (7, 0, 1, 0),
    "sentry": (1, 1, 0, 0),
    "sequential-thinking": (1, 0, 0, 0),
    "sqlite": (6, 1, 1, 0),
    "supabase": (31, 0, 0, 0),
    "terraform": (9, 0, 2, 1),
    "time": (2, 0, 0, 0),
}

# Text rules that look for hidden instructions or characters: real servers must not trigger
# them. MCPS108 is checked separately because one tool legitimately prescribes a workflow.
POISONING_RULES = {f"MCPS{n}" for n in (*range(101, 108), 109, 120, 121, 122)}

# Genuinely high-impact capabilities (exec, destructive) and risky parameters.
EXPECTED_CAPABILITIES = {
    ("MCPS211", "desktop-commander/force_terminate"),
    ("MCPS211", "desktop-commander/kill_process"),
    ("MCPS211", "desktop-commander/start_process"),
    ("MCPS211", "github/delete_file"),
    ("MCPS211", "grafana/delete_annotation"),
    ("MCPS211", "grafana/delete_snapshot"),
    # "Run code/commands in Heroku one-off dyno with network and filesystem access".
    ("MCPS211", "heroku/deploy_one_off_dyno"),
    ("MCPS211", "heroku/pg_kill"),  # Stops Postgres processes (queries, transactions).
    ("MCPS211", "heroku/pg_psql"),  # "Execute SQL queries ... modify schema, manage data".
    ("MCPS211", "kubernetes/exec_in_pod"),
    ("MCPS211", "kubernetes/kubectl_delete"),
    ("MCPS211", "kubernetes/kubectl_generic"),
    ("MCPS211", "kubernetes/uninstall_helm_chart"),
    ("MCPS211", "memory/delete_entities"),
    ("MCPS211", "memory/delete_observations"),
    ("MCPS211", "memory/delete_relations"),
    ("MCPS211", "mongodb/delete-many"),
    ("MCPS211", "mongodb/drop-collection"),
    ("MCPS211", "mongodb/drop-database"),
    ("MCPS211", "mongodb/drop-index"),
    ("MCPS211", "notion/API-delete-a-block"),
    ("MCPS211", "playwright/browser_run_code_unsafe"),
    # Sends an HTTP DELETE request to any URL, which deletes the addressed resource.
    ("MCPS211", "playwright-ea/playwright_delete"),
    ("MCPS211", "supabase/delete_branch"),
    ("MCPS211", "supabase/execute_sql"),
    # Saves a PDF file to disk while declaring readOnlyHint=true.
    ("MCPS212", "playwright/browser_pdf_save"),
    ("MCPS213", "desktop-commander/start_process"),
    ("MCPS213", "heroku/deploy_one_off_dyno"),
    ("MCPS213", "heroku/pg_psql"),
    ("MCPS213", "kubernetes/kubectl_generic"),
    ("MCPS213", "playwright/browser_run_code_unsafe"),
    ("MCPS213", "playwright-ea/playwright_evaluate"),
    ("MCPS213", "puppeteer/puppeteer_evaluate"),
    ("MCPS213", "sqlite/create_table"),
    ("MCPS213", "sqlite/read_query"),
    ("MCPS213", "sqlite/write_query"),
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
    "git-cyanheads": [
        "git_add",
        "git_branch",
        "git_checkout",
        "git_commit",
        "git_diff",
        "git_log",
        "git_reset",
        "git_show",
        "git_status",
    ],
    "github": ["create_branch", "list_branches"],
    "sqlite": ["list_tables"],
}
COUNTERPARTS = {
    "desktop-commander": "filesystem",
    "git-cyanheads": "git",
    "github": "supabase",
    "sqlite": "supabase",
}
EXPECTED_SHARED = {
    ("MCPS106", f"{server}/{name}")
    for first, names in SHARED_NAMES.items()
    for server in (first, COUNTERPARTS[first])
    for name in names
}
EXPECTED_OTHER = {
    # The only long description (6302 characters): a usage guide, low severity.
    ("MCPS110", "desktop-commander/start_search"),
    # "an acceptance-criteria checklist the agent must satisfy before the session is
    # considered shipped": the tool exists to impose a workflow on the agent, which is the
    # steering language this low-severity rule asks to review.
    ("MCPS108", "git-cyanheads/git_wrapup_instructions"),
}
# Prompts, resources and resource templates: none of them was found to be risky. Their
# metadata names only the server's own tools, and no resource points at local files.
EXPECTED_PROMPTS_AND_RESOURCES: set[tuple[str, str]] = set()


def _load(*names: str):
    inventories = []
    for name in names:
        loaded, notices = load_manifest(str(REAL / f"{name}.json"))
        assert notices == []
        inventories.extend(loaded)
    return inventories


@pytest.fixture(scope="module")
def corpus():
    return _load(*SERVERS)


@pytest.fixture(scope="module")
def corpus_findings(corpus):
    return analyze([], corpus)


def test_corpus_is_complete(corpus):
    assert sorted(COUNTS) == SERVERS
    counts = {
        inv.server: (
            len(inv.tools),
            len(inv.prompts),
            len(inv.resources),
            len(inv.resource_templates),
        )
        for inv in corpus
    }
    assert counts == COUNTS
    assert [sum(column) for column in zip(*counts.values(), strict=True)] == [516, 11, 30, 10]


def test_every_kind_was_collected(corpus):
    # An empty list means the server lists none; None would mean "not collected".
    for inv in corpus:
        assert None not in (inv.prompts, inv.resources, inv.resource_templates), inv.server


@pytest.mark.parametrize("server", SERVERS)
def test_no_poisoning_or_unicode_findings(server):
    findings = analyze([], _load(server))
    assert [(f.rule.id, f.message) for f in findings if f.rule.id in POISONING_RULES] == []


@pytest.mark.parametrize("server", SERVERS)
def test_each_server_alone_has_only_expected_findings(server):
    found = {(f.rule.id, f.target) for f in analyze([], _load(server))}
    expected = EXPECTED_CAPABILITIES | EXPECTED_OTHER | EXPECTED_PROMPTS_AND_RESOURCES
    assert found == {item for item in expected if item[1].startswith(f"{server}/")}


def test_together_only_tool_name_clashes_are_added(corpus_findings):
    cross = [f for f in corpus_findings if f.rule.id == "MCPS106"]
    assert cross and all("is also exposed by server(s)" in f.message for f in cross)


def test_findings_match_the_triaged_set(corpus_findings):
    found = Counter((f.rule.id, f.target) for f in corpus_findings)
    assert all(count == 1 for count in found.values())
    expected = EXPECTED_CAPABILITIES | EXPECTED_SHARED | EXPECTED_OTHER
    assert set(found) == expected | EXPECTED_PROMPTS_AND_RESOURCES


def test_prompt_and_resource_findings_match_the_triaged_set(corpus_findings):
    found = {
        (f.rule.id, f.target)
        for f in corpus_findings
        if f.prompt is not None or f.resource is not None
    }
    assert found == EXPECTED_PROMPTS_AND_RESOURCES


def test_corpus_pins_are_stable(tmp_path, corpus):
    # Pinning the corpus and checking it again must not report anything: keys are unique
    # and every definition hashes the same way twice.
    path = tmp_path / "pins.json"
    store = PinStore.load(path)
    first = check_pins(store, [], corpus)
    assert first.findings == []
    assert first.pinned_prompts == 11
    assert first.pinned_resources == 40
    store.save()
    again = check_pins(PinStore.load(path), [], _load(*SERVERS), frozen=True)
    assert again.findings == []


def test_runtime_resources_are_reported_as_low_severity_changes(tmp_path):
    # "everything" adds session resources at run time (gzip-file-as-resource), so a live
    # listing can hold resources that the pinned listing did not: each is reported once as
    # a new resource (LOW) and, once gone, as a removed one (LOW).
    path = tmp_path / "pins.json"
    store = PinStore.load(path)
    check_pins(store, [], _load("everything"))
    store.save()
    (live,) = _load("everything")
    session = {"uri": "demo://resource/session/report.gz", "name": "report.gz"}
    live.resources.append(ResourceDefinition("report.gz", session))
    added = check_pins(PinStore.load(path), [], [live])
    assert [(f.rule.id, f.severity.label, f.resource) for f in added.findings] == [
        ("MCPS408", "low", "demo://resource/session/report.gz")
    ]
    store = PinStore.load(path)
    check_pins(store, [], [live], update=True)
    store.save()
    removed = check_pins(PinStore.load(path), [], _load("everything"))
    assert [(f.rule.id, f.severity.label) for f in removed.findings] == [("MCPS409", "low")]
