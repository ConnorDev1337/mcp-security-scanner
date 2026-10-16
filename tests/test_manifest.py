import json

from mcp_scanner.manifest import dump_inventories, load_manifest, parse_spec

TOOL = {"name": "add", "description": "Adds numbers", "inputSchema": {"type": "object"}}


def test_multi_server_manifest(write_json):
    path = write_json(
        "tools.json",
        {"servers": {"math": {"instructions": "be nice", "tools": [TOOL]}, "b": [TOOL]}},
    )
    inventories, notices = load_manifest(str(path))
    assert not notices
    assert [i.server for i in inventories] == ["math", "b"]
    assert inventories[0].instructions == "be nice"
    assert inventories[0].tools[0].locate("description").line is not None


def test_tools_list_result_uses_name_from_spec(write_json):
    path = write_json("raw.json", {"tools": [TOOL]})
    (inv,), _ = load_manifest(f"calc={path}")
    assert inv.server == "calc"
    (inv,), _ = load_manifest(str(path))
    assert inv.server == "raw"


def test_jsonrpc_response_and_bare_list(write_json):
    rpc = write_json("rpc.json", {"jsonrpc": "2.0", "id": 1, "result": {"tools": [TOOL]}})
    (inv,), _ = load_manifest(str(rpc))
    assert inv.tools[0].pointer == "/result/tools/0"
    bare = write_json("bare.json", [TOOL, {"description": "no name"}])
    (inv,), notices = load_manifest(str(bare))
    assert [t.name for t in inv.tools] == ["add"]
    assert "no name" in notices[0].message


def test_invalid_manifest(write_json, tmp_path):
    _, notices = load_manifest(str(write_json("x.json", {"foo": 1})))
    assert notices[0].level == "error"
    _, notices = load_manifest(str(tmp_path / "nope.json"))
    assert notices[0].message == "tool manifest not found"


def test_parse_spec(tmp_path):
    assert parse_spec("srv=a.json")[0] == "srv"
    assert parse_spec("a.json") == (None, tmp_path.__class__("a.json"))


def test_dump_roundtrip(write_json, tmp_path):
    path = write_json("tools.json", {"servers": {"math": {"instructions": "hi", "tools": [TOOL]}}})
    inventories, _ = load_manifest(str(path))
    out = tmp_path / "dump.json"
    dump_inventories(inventories, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["servers"]["math"]["tools"] == [TOOL]
    again, _ = load_manifest(str(out))
    assert again[0].tools[0].raw == TOOL


PROMPT = {
    "name": "code_review",
    "title": "Request Code Review",
    "description": "Asks the LLM to analyze code quality",
    "arguments": [{"name": "code", "description": "The code to review", "required": True}],
}
RESOURCE = {"uri": "file:///project/src/main.rs", "name": "main.rs", "mimeType": "text/x-rust"}
TEMPLATE = {"uriTemplate": "file:///project/{path}", "name": "Project Files"}


def test_prompts_and_resources_are_loaded_with_locations(write_json):
    entry = {
        "tools": [TOOL],
        "prompts": [PROMPT, {"description": "no name"}],
        "resources": [RESOURCE, {"name": "no uri"}],
        "resourceTemplates": [TEMPLATE],
    }
    path = write_json("tools.json", {"servers": {"srv": entry}})
    (inv,), notices = load_manifest(str(path))
    assert [p.name for p in inv.prompts] == ["code_review"]
    assert [r.uri for r in inv.resources] == ["file:///project/src/main.rs"]
    assert [(t.uri, t.template, t.kind) for t in inv.resource_templates] == [
        ("file:///project/{path}", True, "resource template")
    ]
    assert inv.all_resources() == [*inv.resources, *inv.resource_templates]
    assert inv.prompts[0].pointer == "/servers/srv/prompts/0"
    assert inv.prompts[0].arguments == PROMPT["arguments"]
    assert inv.prompts[0].locate("arguments", 0, "description").line is not None
    assert inv.resource_templates[0].locate("uriTemplate").pointer == (
        "/servers/srv/resourceTemplates/0/uriTemplate"
    )
    messages = sorted(n.message for n in notices)
    assert messages == [
        "prompt #1 of server 'srv' has no name; skipped",
        "resource #1 of server 'srv' has no uri; skipped",
    ]


def test_missing_keys_mean_not_collected(write_json):
    path = write_json(
        "tools.json", {"servers": {"old": {"tools": [TOOL]}, "new": {"prompts": []}}}
    )
    old, new = load_manifest(str(path))[0]
    assert old.prompts is None and old.resources is None and old.resource_templates is None
    assert old.all_resources() == []
    assert new.prompts == [] and new.tools == []


def test_single_server_shapes_accept_prompts_and_resources(write_json):
    rpc = write_json(
        "rpc.json",
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [TOOL], "prompts": [PROMPT]}},
    )
    (inv,), _ = load_manifest(f"srv={rpc}")
    assert inv.prompts[0].pointer == "/result/prompts/0"
    assert inv.resources is None


def test_malformed_feature_lists_are_reported(write_json):
    entry = {"tools": [], "prompts": {"x": 1}, "resources": "nope", "resourceTemplates": [1]}
    (inv,), notices = load_manifest(str(write_json("t.json", {"servers": {"s": entry}})))
    assert inv.prompts is None and inv.resources is None and inv.resource_templates == []
    assert len(notices) == 3


def test_dump_roundtrip_keeps_prompts_resources_and_uncollected_kinds(write_json, tmp_path):
    full = {
        "tools": [TOOL],
        "prompts": [PROMPT],
        "resources": [RESOURCE],
        "resourceTemplates": [TEMPLATE],
    }
    path = write_json("tools.json", {"servers": {"full": full, "legacy": {"tools": [TOOL]}}})
    inventories, _ = load_manifest(str(path))
    out = tmp_path / "dump.json"
    dump_inventories(inventories, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["servers"]["full"] == full
    assert data["servers"]["legacy"] == {"tools": [TOOL]}
    again = {inv.server: inv for inv in load_manifest(str(out))[0]}
    assert again["full"].prompts[0].raw == PROMPT
    assert again["full"].resource_templates[0].raw == TEMPLATE
    assert again["legacy"].prompts is None
