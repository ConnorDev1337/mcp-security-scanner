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
