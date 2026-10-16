"""False positives found on real servers (tests/fixtures/real) and the attacks they must not hide.

Each fix is tested both ways: the legitimate wording is no longer reported and
the malicious or genuinely risky variant still is.
"""

import pytest

from mcp_scanner.engine import analyze
from mcp_scanner.models import ServerInventory, ToolDefinition
from mcp_scanner.rules.capabilities import classify_name


def _inventory(*tools: dict, server: str = "srv", instructions: str | None = None):
    return ServerInventory(
        server, [ToolDefinition(t["name"], t) for t in tools], instructions=instructions
    )


def _found(*inventories) -> set[tuple[str, str]]:
    return {(f.rule.id, f.target) for f in analyze([], list(inventories))}


# --------------------------------------------------------------------------- MCPS211


@pytest.mark.parametrize(
    ("name", "description", "expected"),
    [
        # mcp-server-git: "checkout" is a branch switch, not a payment.
        ("git_checkout", "Switches branches", None),
        ("create_checkout_session", "Creates a Stripe checkout session.", "financial"),
        ("transfer_issue", "Transfer an issue to another repository.", None),
        ("transfer_funds", "Moves money.", "financial"),
        ("charge_card", "Charges the customer.", "financial"),
        ("refund", "Refunds an order.", "financial"),
        # @playwright/mcp: drag and drop, not DROP TABLE.
        (
            "browser_drop",
            "Drop files or MIME-typed data onto an element, as if dragged from outside the page.",
            None,
        ),
        ("drop_table", "Drops a table from the database.", "destructive"),
        ("drop_collection", "", "destructive"),
        ("delete_file", "Delete a file.", "destructive"),
    ],
)
def test_ambiguous_capability_words_are_judged_by_context(name, description, expected):
    assert classify_name(name, description) == expected


@pytest.mark.parametrize("name", ["git_checkout", "browser_drop", "transfer_issue"])
def test_names_without_description_stay_conservative(name):
    # Auto-approve lists carry only names, so ambiguous words still count there.
    assert classify_name(name) is not None


# --------------------------------------------------------------------------- MCPS212


def _read_only(name: str, description: str = "Does something.") -> dict:
    return {"name": name, "description": description, "annotations": {"readOnlyHint": True}}


@pytest.mark.parametrize(
    ("name", "flagged"),
    [
        ("get_commit", False),  # github-mcp-server: reads a commit.
        ("list_merge_requests", False),
        ("search_and_replace", True),
        ("get_or_create_issue", True),
        ("commit_changes", True),
        ("browser_pdf_save", True),
        ("delete_all_files", True),
    ],
)
def test_read_only_hint_contradictions(name, flagged):
    assert (("MCPS212", f"srv/{name}") in _found(_inventory(_read_only(name)))) is flagged
