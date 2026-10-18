"""Property-based tests of hash pinning: pin file round trips and hash stability."""

import json
import random
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from fuzzing import UNICODE_TEXT, provider_tokens, scaled
from mcp_scanner.manifest import dump_inventories, load_manifest
from mcp_scanner.models import (
    PromptDefinition,
    ResourceDefinition,
    ServerConfig,
    ServerInventory,
    ToolDefinition,
)
from mcp_scanner.pinning import (
    PinStore,
    check_pins,
    find_stored_secrets,
    pinned_form,
    sha256_of,
    tool_digests,
)

TOKENS = provider_tokens.map(lambda labelled: labelled[1])
TEXT = (
    UNICODE_TEXT
    | TOKENS
    | st.tuples(UNICODE_TEXT, TOKENS, UNICODE_TEXT).map(" ".join)
    | st.sampled_from(["https://u:hunter2@db.internal/x", "https://h/p?token=abc123456&a=1"])
)
KEYS = TEXT | st.sampled_from(["description", "type", "properties", "default", "enum"])
JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | TEXT,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(KEYS, children, max_size=4),
    max_leaves=20,
)
SALTS = st.binary(min_size=16, max_size=16)


def _shuffled(value, rng: random.Random):
    """Return ``value`` with the keys of every object in a random order."""
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: _shuffled(value[key], rng) for key in keys}
    if isinstance(value, list):
        return [_shuffled(item, rng) for item in value]
    return value


@given(JSON, SALTS, st.randoms(use_true_random=False))
def test_hashes_do_not_depend_on_key_order(value, salt, rng):
    shuffled = _shuffled(value, rng)
    assert sha256_of(shuffled) == sha256_of(value)
    assert pinned_form(shuffled, salt)[1] == pinned_form(value, salt)[1]
    raw = {"name": "t", "description": "d", "inputSchema": value, "annotations": value}
    tool, reordered = ToolDefinition("t", raw), ToolDefinition("t", _shuffled(raw, rng))
    assert tool_digests(reordered, salt) == tool_digests(tool, salt)


@given(JSON, SALTS)
def test_pinned_form_is_idempotent_and_holds_no_secret(value, salt):
    masked, _ = pinned_form(value, salt)
    assert pinned_form(masked, salt)[0] == masked
    assert not [s for s in find_stored_secrets({"s": {"x": masked}}) if s.span.kind == "token"]


TOOLS = st.lists(
    st.fixed_dictionaries(
        {"name": UNICODE_TEXT.filter(bool)},
        optional={"description": TEXT, "inputSchema": JSON, "annotations": JSON},
    ),
    max_size=3,
    unique_by=lambda tool: tool["name"],
)
INVENTORIES = st.lists(
    st.builds(
        lambda server, tools, instructions, prompts, resources: ServerInventory(
            server,
            [ToolDefinition(tool["name"], tool) for tool in tools],
            instructions=instructions,
            prompts=[PromptDefinition(p["name"], p) for p in prompts],
            resources=[ResourceDefinition(r.get("name", ""), r) for r in resources],
        ),
        UNICODE_TEXT,
        TOOLS,
        st.none() | TEXT,
        st.lists(
            st.fixed_dictionaries({"name": TEXT}, optional={"description": TEXT}), max_size=2
        ),
        st.lists(st.fixed_dictionaries({"uri": TEXT}, optional={"name": TEXT}), max_size=2),
    ),
    max_size=3,
    unique_by=lambda inv: inv.server,
)
CONFIGS = st.lists(
    st.builds(
        ServerConfig,
        name=UNICODE_TEXT,
        client=st.sampled_from(["claude-desktop", "vscode", "codex"]),
        transport=st.sampled_from(["stdio", "http"]),
        command=st.none() | TEXT,
        args=st.lists(TEXT, max_size=3),
        env=st.dictionaries(TEXT, TEXT, max_size=2),
        url=st.none() | TEXT,
    ),
    max_size=3,
    unique_by=lambda config: (config.name, config.client),
)


@scaled(0.5)
@given(CONFIGS, INVENTORIES)
def test_pin_files_round_trip(configs, inventories):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pins.json"
        store = PinStore.load(path)
        outcome = check_pins(store, configs, inventories, now="2026-01-01T00:00:00+00:00")
        assert outcome.findings == []
        store.save()
        loaded = PinStore.load(path)
        assert loaded.version == 3 and loaded.salt == store.salt
        assert loaded.servers == json.loads(json.dumps(store.servers))
        assert loaded.stored_secrets == []
        again = check_pins(loaded, configs, inventories, now="2026-02-01T00:00:00+00:00")
        assert again.findings == [] and not again.dirty
        loaded.save()  # Saving an unchanged store writes the same servers.
        assert PinStore.load(path).servers == loaded.servers


@scaled(0.5)
@given(INVENTORIES, st.booleans())
def test_masked_dumps_verify_against_live_pins_and_back(inventories, pin_live_first):
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        dump, pins = folder / "dump.json", folder / "pins.json"
        dump_inventories(inventories, dump)
        text = dump.read_text(encoding="utf-8")
        dumped, notices = load_manifest(str(dump))
        assert not [n for n in notices if n.level == "error"]
        assert len(dumped) == len(inventories)
        assert not [s for s in find_stored_secrets(json.loads(text)) if s.span.kind == "token"]
        first, second = (inventories, dumped) if pin_live_first else (dumped, inventories)
        store = PinStore.load(pins)
        check_pins(store, [], first)
        store.save()
        for frozen in (True, False):
            outcome = check_pins(PinStore.load(pins), [], second, frozen=frozen)
            assert outcome.findings == []


# --------------------------------------------------------------------------- regressions


def test_token_used_as_env_name_is_not_stored(tmp_path):
    # Found by fuzzing: launch records kept environment variable names verbatim, so a
    # token pasted as a name was written to the pin file and reported (MCPS304) on
    # every later scan.
    token = "xoxa-" + "".join(random.Random(3).choices("0123456789", k=10))
    server = ServerConfig("s", "claude-desktop", "stdio", command="npx", env={token: ""})
    path = tmp_path / "pins.json"
    store = PinStore.load(path)
    check_pins(store, [server], [])
    store.save()
    assert token not in path.read_text(encoding="utf-8")
    loaded = PinStore.load(path)
    assert loaded.stored_secrets == []
    assert check_pins(loaded, [server], []).findings == []


def test_env_names_stored_by_earlier_versions_are_masked_on_load(tmp_path):
    token = "xoxa-" + "".join(random.Random(4).choices("0123456789", k=10))
    server = ServerConfig("s", "claude-desktop", "stdio", command="npx", env={token: ""})
    path = tmp_path / "pins.json"
    store = PinStore.load(path)
    check_pins(store, [server], [])
    store.servers["s"]["launch"]["claude-desktop"]["env_keys"] = [token]  # As stored before.
    store.save()
    loaded = PinStore.load(path)
    outcome = check_pins(loaded, [server], [])
    assert [f.rule.id for f in outcome.findings] == ["MCPS304"] and outcome.dirty
    loaded.save()
    assert token not in path.read_text(encoding="utf-8")
    assert check_pins(PinStore.load(path), [server], []).findings == []


def test_tokens_in_names_never_become_pin_keys(tmp_path):
    # Found by fuzzing: servers, tools and prompts were keyed by their raw name, so a
    # token in a name was written to the pin file.
    rng = random.Random(5)
    token = "rk_live_" + "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
    tool = ToolDefinition(token, {"name": token, "description": "d"})
    prompt = PromptDefinition(token, {"name": token})
    inventory = ServerInventory(token, [tool], prompts=[prompt])
    path = tmp_path / "pins.json"
    store = PinStore.load(path)
    check_pins(store, [], [inventory])
    store.save()
    assert token not in path.read_text(encoding="utf-8")
    loaded = PinStore.load(path)
    assert loaded.stored_secrets == []
    assert check_pins(loaded, [], [inventory]).findings == []


def test_keys_that_mask_alike_keep_every_value():
    # Found by fuzzing: two token-shaped keys of one format and length mask to the same
    # key, so one value was dropped (its changes went undetected) and which one
    # depended on the key order.
    rng = random.Random(6)
    first, second = ("lin_api_" + "".join(rng.choices("abcdefXYZ0123", k=40)) for _ in "12")
    value = {first: "one", second: "two"}
    masked, digest = pinned_form(value, b"salt")
    assert sorted(masked.values()) == ["one", "two"]
    assert pinned_form({second: "two", first: "one"}, b"salt")[1] == digest
    assert pinned_form({first: "one", second: "changed"}, b"salt")[1] != digest
