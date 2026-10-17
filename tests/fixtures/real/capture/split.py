"""Split a scanner dump into one corpus file per server (see ../README.md).

Usage: ``PYTHONPATH=src python split.py DUMP TARGET_DIR``

Hidden characters (invisible, bidirectional, tag ...) are written as JSON
``\\uXXXX`` escapes, so the files never contain them literally.
"""

import json
import sys
from pathlib import Path

from mcp_scanner.textutil import is_hidden_char


def escape_hidden(text: str) -> str:
    """Replace each hidden character of a JSON document by its ``\\uXXXX`` escape."""
    out = []
    for ch in text:
        if is_hidden_char(ch) and ch not in "\n\t\r":
            data = ch.encode("utf-16-be")
            out.extend(
                "\\u" + format(int.from_bytes(data[i : i + 2]), "04x")
                for i in range(0, len(data), 2)
            )
        else:
            out.append(ch)
    return "".join(out)


def main(dump_path: str, target_dir: str) -> None:
    dump = json.loads(Path(dump_path).read_text(encoding="utf-8"))
    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)
    for name, entry in dump["servers"].items():
        payload = {
            "generator": dump["generator"],
            "generated_at": dump["generated_at"],
            "servers": {name: entry},
        }
        text = escape_hidden(json.dumps(payload, indent=2, ensure_ascii=False)) + "\n"
        assert json.loads(text) == payload
        (target / f"{name}.json").write_text(text, encoding="utf-8", newline="\n")
        kinds = ("tools", "prompts", "resources", "resourceTemplates")
        print(name, *(len(entry.get(kind) or ()) for kind in kinds))


if __name__ == "__main__":
    main(*sys.argv[1:3])
