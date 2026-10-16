import hashlib

from mcp_scanner.models import Finding, Location
from mcp_scanner.rules.catalog import get


def test_finding_target_names_the_subject():
    rule = get("MCPS101")
    assert Finding(rule, "m", Location(), server="s", tool="t").target == "s/t"
    assert Finding(rule, "m", Location(), server="s", prompt="p").target == "s/prompt:p"
    resource = Finding(rule, "m", Location(), server="s", resource="file:///x")
    assert resource.target == "s/resource:file:///x"
    assert resource.subject == "resource:file:///x"
    assert Finding(rule, "m", Location(), server="s").target == "s"
    assert Finding(rule, "m", Location()).target == "-"


def test_fingerprints_distinguish_subjects_and_stay_stable_for_tools():
    rule = get("MCPS101")
    tool = Finding(rule, "m", Location(), server="s", tool="x", evidence="e")
    prompt = Finding(rule, "m", Location(), server="s", prompt="x", evidence="e")
    resource = Finding(rule, "m", Location(), server="s", resource="x", evidence="e")
    assert len({tool.fingerprint(), prompt.fingerprint(), resource.fingerprint()}) == 3
    # Tool fingerprints are unchanged by the prompt/resource fields (existing SARIF alerts).
    legacy = hashlib.sha256("\x1f".join(["MCPS101", "s", "x", "", "e"]).encode()).hexdigest()
    assert tool.fingerprint() == legacy[:32]
