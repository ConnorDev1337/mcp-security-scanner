"""Command-line interface (``mcp-scanner``).

Exit codes: 0 = no finding at or above ``--fail-on``; 1 = such findings exist;
2 = usage error, or an input (config, manifest, pin file) could not be read
(unless code 1 applies).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import TOOL_NAME, __version__, loader
from .manifest import dump_inventories
from .models import Severity
from .pinning import ENV_PIN_PATH, default_pin_path
from .reporters import display_path, json_report, sarif, table
from .rules.catalog import all_rules
from .scanner import ScanOptions, ScanReport, run_scan

SEVERITIES = [s.label for s in sorted(Severity, reverse=True)]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="Defensive static scanner for MCP client configurations and the tool, "
        "prompt and resource definitions of MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser(
        "scan",
        help="scan MCP configs and tool, prompt and resource definitions",
        description="Scan MCP client configuration files and tool, prompt and resource "
        "definitions for risks. "
        "Without CONFIG or --tools, well-known client config locations are discovered.",
    )
    scan.add_argument("configs", nargs="*", metavar="CONFIG", help="MCP client config file(s)")
    scan.add_argument(
        "--discover", action="store_true", help="also scan well-known client config locations"
    )
    scan.add_argument(
        "-t",
        "--tools",
        action="append",
        default=[],
        metavar="[NAME=]FILE",
        help="definitions captured offline (tools/list result or multi-server dump with "
        "optional prompts, resources and resourceTemplates)",
    )
    scan.add_argument(
        "--introspect",
        action="store_true",
        help="list the tools, prompts and resources of each configured server (metadata "
        "only; resources are never read). WARNING: this EXECUTES stdio server commands; run "
        "it in a sandbox",
    )
    scan.add_argument("--timeout", type=float, default=20.0, help="introspection timeout (s)")
    scan.add_argument(
        "--dump-tools",
        metavar="FILE",
        help="save collected tool, prompt and resource definitions (re-loadable with --tools)",
    )

    pins = scan.add_argument_group("hash pinning")
    pins.add_argument(
        "--pins",
        metavar="FILE",
        help=f"pin file (default: ${ENV_PIN_PATH} or ~/.mcp-scanner/pins.json)",
    )
    pins.add_argument("--no-pins", action="store_true", help="disable hash pinning")
    pins.add_argument(
        "--update-pins", action="store_true", help="approve the current state (re-pin changes)"
    )
    pins.add_argument(
        "--frozen-pins",
        action="store_true",
        help="never write the pin file; report anything not approved (for CI)",
    )

    out = scan.add_argument_group("output")
    out.add_argument("-f", "--format", choices=["table", "json", "sarif"], default="table")
    out.add_argument("-o", "--output", metavar="FILE", help="write --format output to FILE")
    out.add_argument("--json", dest="json_out", metavar="FILE", help="also write a JSON report")
    out.add_argument("--sarif", dest="sarif_out", metavar="FILE", help="also write SARIF 2.1.0")
    out.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide below this")
    out.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "none"],
        default="high",
        help="exit 1 if a finding at or above this severity exists (default: high)",
    )
    out.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    out.add_argument("--root", metavar="DIR", help="base dir for relative paths (default: cwd)")

    rules = sub.add_parser("rules", help="list the rule catalog")
    rules.add_argument("-f", "--format", choices=["table", "json", "markdown"], default="table")

    sub.add_parser("discover", help="list MCP client config files found on this machine")
    return parser


def _enable_windows_ansi() -> bool:
    """Enable ANSI escape processing on the Windows console; return whether it is on."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # 0x0004 is ENABLE_VIRTUAL_TERMINAL_PROCESSING.
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


def _use_color(choice: str) -> bool:
    if choice != "auto":
        return choice == "always"
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not sys.stdout.isatty():
        return False
    return _enable_windows_ansi() if os.name == "nt" else True


def _write(path: str, content: str) -> None:
    target = Path(path)
    if target.parent != Path():
        target.parent.mkdir(parents=True, exist_ok=True)
    # LF on every platform, as reports may be committed; a lone surrogate, which only
    # appears inside JSON strings, is written as its escape.
    target.write_text(content, encoding="utf-8", errors="backslashreplace", newline="\n")


def _render(fmt: str, report: ScanReport, args: argparse.Namespace, root: Path) -> str:
    min_severity = Severity.parse(args.min_severity)
    if fmt == "json":
        return json_report.render(report, root=root, min_severity=min_severity)
    if fmt == "sarif":
        return sarif.render(report, root=root, min_severity=min_severity)
    color = _use_color(args.color) and not args.output
    return table.render(report, color=color, root=root, min_severity=min_severity)


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.update_pins and args.frozen_pins:
        print("error: --update-pins and --frozen-pins are mutually exclusive", file=sys.stderr)
        return 2
    if args.no_pins and (args.update_pins or args.frozen_pins or args.pins):
        print("error: --no-pins cannot be combined with other pin options", file=sys.stderr)
        return 2
    root = Path(args.root) if args.root else Path.cwd()
    options = ScanOptions(
        configs=args.configs,
        discover=args.discover,
        tool_manifests=args.tools,
        introspect=args.introspect,
        timeout=args.timeout,
        pins=None if args.no_pins else Path(args.pins) if args.pins else default_pin_path(),
        update_pins=args.update_pins,
        frozen_pins=args.frozen_pins,
    )
    if args.introspect:
        print(
            "warning: --introspect executes the configured stdio server commands",
            file=sys.stderr,
        )
    report = run_scan(options)

    if args.dump_tools:
        dump_inventories(report.inventories, args.dump_tools)
    output = _render(args.format, report, args, root)
    if args.output:
        _write(args.output, output)
    else:
        sys.stdout.write(output)
    if args.json_out:
        _write(args.json_out, _render("json", report, args, root))
    if args.sarif_out:
        _write(args.sarif_out, _render("sarif", report, args, root))

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in report.findings):
            return 1
    if any(n.level == "error" for n in report.notices):
        return 2
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = all_rules()
    if args.format == "json":
        payload = [
            {
                "id": r.id,
                "name": r.name,
                "title": r.title,
                "severity": r.severity.label,
                "category": r.category,
                "description": r.description,
                "remediation": r.remediation,
            }
            for r in rules
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    elif args.format == "markdown":
        lines = ["| ID | Severity | Category | Title |", "|----|----------|----------|-------|"]
        lines += [f"| {r.id} | {r.severity.label} | {r.category} | {r.title} |" for r in rules]
        sys.stdout.write("\n".join(lines) + "\n")
    else:
        for r in rules:
            sys.stdout.write(f"{r.id}  {r.severity.label:<8}  {r.category:<14}  {r.title}\n")
    return 0


def _cmd_discover(_: argparse.Namespace) -> int:
    found = loader.discover()
    if not found:
        print("No MCP client configuration files found.")
    for client, path in found:
        print(f"{client:<15} {display_path(str(path))}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit code."""
    # Untrusted text must never crash output on consoles with a narrow encoding, and a
    # report redirected to a file gets LF line endings, as with --output.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace", newline="\n")
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "discover":
        return _cmd_discover(args)
    parser.print_help()
    return 2
