"""MCPS001 and MCPS201-MCPS210: risky launch configuration and permissions."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..jsonloc import SourceDocument
from ..models import Finding, Location, ServerConfig, Severity
from ..textutil import sanitize
from .capabilities import classify_name
from .catalog import get

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"})
POWERSHELL = frozenset({"powershell", "pwsh"})
ELEVATORS = frozenset({"sudo", "doas", "pkexec", "runas", "gsudo", "su"})
DOCKER_LIKE = frozenset({"docker", "podman", "nerdctl"})
CODE_FLAGS = {
    "python": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "bun": frozenset({"-e", "--eval"}),
    "ruby": frozenset({"-e"}),
    "perl": frozenset({"-e", "-E"}),
    "php": frozenset({"-r"}),
}

_POSIX_META = re.compile(r"[|;&<>`\n]|\$\(")
_CMD_META = re.compile(r"[|&<>^\n]")
_PS_META = re.compile(r"[|;&<>`\n]|\$\(|\biex\b|invoke-expression", re.IGNORECASE)
_DOWNLOAD_EXEC = re.compile(
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(?:sudo\s+)?"
    r"(?:sh|bash|zsh|dash|python[\d.]*|node|perl|ruby|iex|invoke-expression|pwsh|powershell)\b"
    r"|\biex\s*\(\s*(?:new-object\s+net\.webclient|\(?\s*(?:iwr|irm|invoke-webrequest|"
    r"invoke-restmethod))"
    r"|\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- launch analysis


@dataclass
class Inline:
    """A script passed inline to a shell or interpreter (``sh -c``, ``python -c``, ...)."""

    kind: str  # "shell" | "code" | "encoded"
    interpreter: str
    script: str
    chained: bool  # True if the script cannot be reduced to a single inner command.


@dataclass
class Launch:
    """The command that really runs once env/sudo/shell wrappers are peeled off."""

    base: str
    args: list[str]
    wrappers: list[str] = field(default_factory=list)
    inline: Inline | None = None


def command_base(command: str) -> str:
    """Return the lowercase executable name without directory or Windows extension.

    Python and Node.js variants are normalized to ``python`` and ``node``.
    """
    name = re.split(r"[\\/]", command.strip().strip("\"'"))[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1", ".com"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    if re.fullmatch(r"python[\d.]*w?|py", name):
        return "python"
    return "node" if name == "nodejs" else name


def _split(script: str, posix: bool) -> list[str] | None:
    try:
        tokens = shlex.split(script, posix=posix)
    except ValueError:
        return None
    return [t.strip('"') for t in tokens] if not posix else tokens


def _continue(inline: Inline, wrappers: list[str], posix: bool = True) -> Launch:
    """Analyze the command inside an inline script, unless it chains several commands."""
    tokens = None if inline.chained else _split(inline.script, posix)
    if not tokens:
        return Launch(inline.interpreter, [], wrappers, inline)
    inner = analyze_launch(tokens[0], tokens[1:])
    inner.wrappers = wrappers + inner.wrappers
    inner.inline = inner.inline or inline
    return inner


_RUNAS_OPT = re.compile(r"^/[a-z]+(?::.*)?$", re.IGNORECASE)
_PS_VALUE_OPTS = (
    "-executionpolicy",
    "-windowstyle",
    "-version",
    "-configurationname",
    "-outputformat",
    "-inputformat",
    "-psconsolefile",
    "-workingdirectory",
    "-settingsfile",
    "-custompipename",
)


def _ps_takes_value(option: str) -> bool:
    """Return whether a PowerShell option consumes the next argument.

    PowerShell accepts any unambiguous prefix of a parameter name.
    """
    if option in {"-ep", "-ex", "-wd", "-w", "-v"}:
        return True
    return len(option) >= 3 and any(o.startswith(option) for o in _PS_VALUE_OPTS)


def _decode_powershell(payload: str) -> str | None:
    """Decode an ``-EncodedCommand`` payload (base64 of UTF-16LE); None if invalid."""
    try:
        return base64.b64decode(payload, validate=True).decode("utf-16-le")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def analyze_launch(command: str, args: list[str]) -> Launch:
    """Peel off up to eight levels of env/sudo/shell wrappers to find what really runs."""
    base, rest, wrappers = command_base(command), list(args), []
    for _ in range(8):
        if base == "env":
            i = 0
            while i < len(rest) and (rest[i].startswith("-") or "=" in rest[i]):
                i += 2 if rest[i] in {"-u", "--unset", "-C", "--chdir", "-S"} else 1
            if i >= len(rest):
                break
            wrappers.append("env")
            base, rest = command_base(rest[i]), rest[i + 1 :]
            continue
        if base in ELEVATORS:
            wrappers.append(base)
            i = 0
            while i < len(rest) and (
                rest[i].startswith("-") or (base == "runas" and _RUNAS_OPT.match(rest[i]))
            ):
                i += 2 if rest[i] in {"-u", "-g", "-C", "-D", "-h", "-p", "-U", "--user"} else 1
            if i >= len(rest):
                break
            tokens = _split(rest[i], posix=True) if " " in rest[i] else [rest[i]]
            if not tokens:
                break
            base, rest = command_base(tokens[0]), tokens[1:] + rest[i + 1 :]
            continue
        if base == "cmd":
            index = next((i for i, a in enumerate(rest) if a.lower() in {"/c", "/k", "/r"}), None)
            if index is None:
                break
            script = " ".join(rest[index + 1 :])
            inline = Inline("shell", "cmd", script, bool(_CMD_META.search(script)))
            return _continue(inline, [*wrappers, "cmd"], posix=False)
        if base in SHELLS:
            index = next(
                (i for i, a in enumerate(rest) if re.fullmatch(r"-[a-z]*c[a-z]*", a)), None
            )
            if index is None:
                break
            script = rest[index + 1] if index + 1 < len(rest) else ""
            inline = Inline("shell", base, script, bool(_POSIX_META.search(script)))
            return _continue(inline, [*wrappers, base])
        if base in POWERSHELL:
            i = 0
            while i < len(rest):
                low = rest[i].lower()
                if low in {"-e", "-ec"} or (len(low) >= 3 and "-encodedcommand".startswith(low)):
                    payload = rest[i + 1] if i + 1 < len(rest) else ""
                    decoded = _decode_powershell(payload)
                    inline = Inline("encoded", base, decoded or payload, True)
                    return Launch(base, rest, wrappers, inline)
                if len(low) >= 2 and "-command".startswith(low):
                    script = " ".join(rest[i + 1 :])
                    inline = Inline("shell", base, script, bool(_PS_META.search(script)))
                    return _continue(inline, [*wrappers, base])
                if low in {"-file", "-f"} or not low.startswith("-"):
                    break
                i += 2 if _ps_takes_value(low) else 1
            break
        flags = CODE_FLAGS.get(base)
        if flags:
            for i, arg in enumerate(rest):
                if arg in flags:
                    code = rest[i + 1] if i + 1 < len(rest) else ""
                    return Launch(base, rest, wrappers, Inline("code", base, code, True))
                if not arg.startswith("-") or arg == "-m":
                    break
        break
    return Launch(base, rest, wrappers)


# --------------------------------------------------------------------------- package pinning
# The *_spec helpers extract the package a runner installs; the *_unpinned helpers
# return why that spec is not pinned to an exact version, or None.

_EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")
_EXACT_PEP440 = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
_GIT_SHA = re.compile(r"[#@]([0-9a-f]{40})$")
_NPX_VALUE_OPTS = frozenset(
    {"--cache", "--userconfig", "--registry", "-c", "--call", "--prefix", "-w", "--workspace"}
)
_UVX_VALUE_OPTS = frozenset(
    {
        "--with",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "--directory",
        "--project",
        "--env-file",
        "--cache-dir",
        "--config-file",
        "--with-requirements",
        "--with-editable",
        "--constraints",
        "-c",
        "--overrides",
        "--refresh-package",
        "--reinstall-package",
        "--upgrade-package",
        "-P",
        "--python-platform",
        "--exclude-newer",
        "--index-strategy",
        "--keyring-provider",
        "--resolution",
        "--prerelease",
        "--link-mode",
        "--color",
    }
)


def _is_local(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "\\", "file:")) or bool(
        re.match(r"^[A-Za-z]:[\\/]", spec)
    )


def _npx_spec(args: list[str]) -> str | None:
    from_flag, i = None, 0
    while i < len(args):
        arg = args[i]
        if arg in {"-p", "--package"}:
            from_flag = args[i + 1] if i + 1 < len(args) else None
            i += 2
        elif arg.startswith("--package="):
            from_flag = arg.split("=", 1)[1]
            i += 1
        elif arg.startswith("-"):
            i += 2 if arg in _NPX_VALUE_OPTS else 1
        else:
            return from_flag or arg
    return from_flag


def _uvx_spec(args: list[str]) -> str | None:
    from_flag, i = None, 0
    while i < len(args):
        arg = args[i]
        if arg == "--from":
            from_flag = args[i + 1] if i + 1 < len(args) else None
            i += 2
        elif arg.startswith("--from="):
            from_flag = arg.split("=", 1)[1]
            i += 1
        elif arg.startswith("-"):
            i += 2 if arg in _UVX_VALUE_OPTS else 1
        else:
            return from_flag or arg
    return from_flag


def _pipx_spec(args: list[str]) -> str | None:
    for i, arg in enumerate(args):
        if arg == "--spec" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--spec="):
            return arg.split("=", 1)[1]
    return next((a for a in args if not a.startswith("-")), None)


def _npm_unpinned(spec: str) -> str | None:
    if _is_local(spec):
        return None
    if re.match(r"^(?:git\+|git:|github:|https?:)", spec):
        return None if _GIT_SHA.search(spec) else "git/URL dependency without a commit hash"
    spec = spec.removeprefix("npm:")
    body = spec[1:] if spec.startswith("@") else spec
    _, sep, version = body.partition("@")
    if not sep:
        return "no version specified"
    if _EXACT_SEMVER.match(version):
        return None
    return f"floating version {version!r}"


def _py_unpinned(spec: str) -> str | None:
    if _is_local(spec):
        return None
    if spec.startswith("git+"):
        return None if _GIT_SHA.search(spec) else "git dependency without a commit hash"
    match = re.match(r"^[A-Za-z0-9_.\-\[\],]+\s*(===|==|@)\s*([^\s;]+)$", spec)
    if match:
        version = match.group(2)
        return None if _EXACT_PEP440.match(version) else f"floating version {version!r}"
    if re.search(r"[<>=!~]", spec):
        return "version range instead of an exact pin"
    return "no version specified"


def _image_unpinned(image: str) -> tuple[str, Severity] | None:
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.split(":", 1)[1]
        if tag == "latest":
            return "uses the mutable 'latest' tag", Severity.MEDIUM
        return f"tag {tag!r} is mutable (no @sha256 digest)", Severity.LOW
    return "has no tag (implicitly 'latest')", Severity.MEDIUM


# --------------------------------------------------------------------------- docker parsing

_DOCKER_SHORT = {
    "-e": "--env",
    "-v": "--volume",
    "-p": "--publish",
    "-u": "--user",
    "-w": "--workdir",
    "-h": "--hostname",
    "-l": "--label",
    "-m": "--memory",
}
_DOCKER_VALUE_OPTS = frozenset(
    {
        "--env",
        "--volume",
        "--publish",
        "--user",
        "--workdir",
        "--hostname",
        "--label",
        "--memory",
        "--name",
        "--network",
        "--net",
        "--entrypoint",
        "--env-file",
        "--mount",
        "--cpus",
        "--platform",
        "--pull",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "--add-host",
        "--device",
        "--ipc",
        "--pid",
        "--uts",
        "--userns",
        "--cgroupns",
        "--restart",
        "--runtime",
        "--tmpfs",
        "--ulimit",
        "--log-driver",
        "--log-opt",
        "--gpus",
        "--dns",
        "--stop-signal",
        "--shm-size",
        "--group-add",
        "--label-file",
        "--expose",
        "--health-cmd",
        "--cidfile",
    }
)


def parse_docker_run(args: list[str]) -> tuple[list[tuple[str, str | None]], str | None] | None:
    """Parse ``docker run`` arguments into ``(options, image)``; None for other commands.

    Short options are expanded to their long names; flags without a value map to None.
    """
    if args[:1] == ["run"]:
        rest = args[1:]
    elif args[:2] == ["container", "run"]:
        rest = args[2:]
    else:
        return None
    options: list[tuple[str, str | None]] = []
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            return options, rest[i + 1] if i + 1 < len(rest) else None
        if arg.startswith("--"):
            if "=" in arg:
                name, value = arg.split("=", 1)
                options.append((name, value))
                i += 1
            elif arg in _DOCKER_VALUE_OPTS:
                options.append((arg, rest[i + 1] if i + 1 < len(rest) else ""))
                i += 2
            else:
                options.append((arg, None))
                i += 1
            continue
        if arg.startswith("-") and len(arg) > 1:
            short = arg[:2]
            if short in _DOCKER_SHORT:
                if len(arg) > 2:
                    options.append((_DOCKER_SHORT[short], arg[2:].lstrip("=")))
                    i += 1
                else:
                    options.append(
                        (_DOCKER_SHORT[short], rest[i + 1] if i + 1 < len(rest) else "")
                    )
                    i += 2
            else:
                options.append((arg, None))
                i += 1
            continue
        return options, arg
    return options, None


_HOME_ALIASES = frozenset(
    {
        "~",
        "$home",
        "${home}",
        "%userprofile%",
        "%homepath%",
        "${env:home}",
        "${env:userprofile}",
        "${userhome}",
        "/root",
    }
)


def path_breadth(value: str) -> str | None:
    """Classify a path argument as filesystem ``root``, a ``home`` dir, or neither."""
    raw = value.strip().strip("\"'")
    if not raw:
        return None
    norm = raw.replace("\\", "/")
    if norm != "/":
        norm = norm.rstrip("/")
    low = norm.lower()
    if (
        low == "/"
        or re.fullmatch(r"[a-z]:", low)
        or low in {"/home", "/users", "c:/users", "/mnt"}
    ):
        return "root"
    if low in _HOME_ALIASES:
        return "home"
    if re.fullmatch(r"/(?:home|users)/[^/]+|[a-z]:/users/[^/]+|/mnt/[a-z]/users/[^/]+", low):
        return "home"
    return None


def _mount_source(option: str, value: str) -> str | None:
    """Return the host path of a ``--volume`` or bind ``--mount`` option, if any."""
    if option == "--mount":
        fields = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
        if fields.get("type", "bind") != "bind":
            return None
        return fields.get("source") or fields.get("src")
    if re.match(r"^[A-Za-z]:[\\/]", value):  # The first colon belongs to the drive letter.
        return value[:2] + value[2:].split(":")[0]
    return value.split(":")[0]


_SENSITIVE_HOST_PATHS = frozenset(
    {
        "/etc",
        "/root",
        "/proc",
        "/sys",
        "/dev",
        "/var/run",
        "/run",
        "/boot",
        "/var/lib/docker",
    }
)


def _sensitive_mount(source: str) -> tuple[str, Severity] | None:
    low = source.lower().replace("\\", "/")
    if any(s in low for s in ("docker.sock", "docker_engine", "podman.sock", "containerd.sock")):
        return "mounts the container engine socket (full control of the host)", Severity.CRITICAL
    breadth = path_breadth(source)
    if breadth:
        what = "host root filesystem" if breadth == "root" else "a home directory"
        return f"mounts {what} ({source})", Severity.HIGH
    if low.rstrip("/") in _SENSITIVE_HOST_PATHS:
        return f"mounts sensitive host path {source}", Severity.HIGH
    if re.search(r"(?:^|/)\.(?:ssh|aws|kube|gnupg|docker|config/gcloud)(?:/|$)", low):
        return f"mounts a credential directory ({source})", Severity.HIGH
    return None


# --------------------------------------------------------------------------- checks


def _finding(
    rule_id: str,
    server: ServerConfig,
    message: str,
    location: Location,
    *,
    field: str | None = None,
    evidence: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    return Finding(
        get(rule_id),
        message,
        location,
        server=server.name,
        field=field,
        evidence=evidence,
        severity=severity,
    )


def _arg_location(server: ServerConfig, arg: str) -> Location:
    if arg in server.args:
        return server.locate("args", server.args.index(arg))
    return server.locate("args")


def _check_inline(server: ServerConfig, launch: Launch) -> Iterator[Finding]:
    inline = launch.inline
    if inline is None:
        return
    location = server.locate("args")
    evidence = sanitize(inline.script, 160) if inline.script else None
    if inline.kind == "encoded":
        message = f"Server is launched with an encoded {inline.interpreter} command"
        severity = Severity.HIGH
    elif inline.kind == "code":
        message = f"Server runs inline {inline.interpreter} code"
        severity = Severity.HIGH
    elif inline.chained:
        message = (
            f"Server is launched through '{inline.interpreter}' with shell metacharacters "
            "(command chaining or redirection)"
        )
        severity = Severity.HIGH
    else:
        message = (
            f"Server is launched through a '{inline.interpreter}' wrapper "
            f"(inner command: {launch.base})"
        )
        severity = Severity.LOW
    yield _finding(
        "MCPS201", server, message, location, field="args", evidence=evidence, severity=severity
    )


def _check_remote_exec(server: ServerConfig) -> Iterator[Finding]:
    command_line = " ".join([server.command or "", *server.args])
    match = _DOWNLOAD_EXEC.search(command_line)
    if match:
        yield _finding(
            "MCPS202",
            server,
            "Launch command downloads and executes remote code",
            server.locate("args"),
            field="args",
            evidence=sanitize(match.group(), 160),
        )


def _check_elevation(server: ServerConfig, launch: Launch) -> Iterator[Finding]:
    used = [w for w in launch.wrappers if w in ELEVATORS]
    if launch.base in ELEVATORS:
        used.append(launch.base)
    if used:
        yield _finding(
            "MCPS203",
            server,
            f"Server is launched through '{used[0]}' with elevated privileges",
            server.locate("command"),
            field="command",
        )


def _check_unpinned(server: ServerConfig, launch: Launch) -> Iterator[Finding]:
    base, args = launch.base, launch.args
    spec: str | None = None
    problem: str | None = None
    severity: Severity | None = None
    if base in {"npx", "bunx", "pnpx"}:
        spec = _npx_spec(args)
    elif (
        (base == "npm" and args[:1] in (["exec"], ["x"]))
        or (base in {"pnpm", "yarn"} and args[:1] == ["dlx"])
        or (base == "bun" and args[:1] == ["x"])
    ):
        spec = _npx_spec(args[1:])
    elif base in {"uvx"} or (base == "uv" and args[:2] == ["tool", "run"]):
        spec = _uvx_spec(args if base == "uvx" else args[2:])
        problem = _py_unpinned(spec) if spec else None
    elif base == "pipx" and args[:1] == ["run"]:
        spec = _pipx_spec(args[1:])
        problem = _py_unpinned(spec) if spec else None
    elif base in DOCKER_LIKE:
        parsed = parse_docker_run(args)
        if parsed and parsed[1]:
            spec = parsed[1]
            result = _image_unpinned(spec)
            if result:
                problem, severity = result
    elif base == "go" and args[:1] == ["run"]:
        spec = next((a for a in args[1:] if "@" in a), None)
        if spec and spec.endswith("@latest"):
            problem = "floating version 'latest'"
    if spec and problem is None and base not in DOCKER_LIKE | {"uvx", "uv", "pipx", "go"}:
        problem = _npm_unpinned(spec)
    if spec and problem:
        yield _finding(
            "MCPS204",
            server,
            f"{base} runs {spec!r}: {problem}",
            _arg_location(server, spec),
            field="args",
            evidence=sanitize(spec),
            severity=severity,
        )


def _check_container(server: ServerConfig, launch: Launch) -> Iterator[Finding]:
    if launch.base not in DOCKER_LIKE:
        return
    parsed = parse_docker_run(launch.args)
    if not parsed:
        return
    for option, value in parsed[0]:
        problem: tuple[str, Severity] | None = None
        if option == "--privileged" and value in (None, "true"):
            problem = "runs with --privileged", Severity.HIGH
        elif option in {"--pid", "--network", "--net", "--ipc", "--uts", "--userns", "--cgroupns"}:
            if value == "host":
                problem = f"shares the host {option.lstrip('-')} namespace", Severity.HIGH
        elif option == "--cap-add" and value:
            problem = f"adds kernel capability {value}", Severity.HIGH
        elif option == "--security-opt" and value:
            low = value.lower().replace(":", "=")
            if "unconfined" in low or "no-new-privileges=false" in low:
                problem = f"weakens confinement ({value})", Severity.HIGH
        elif option == "--device" and value:
            problem = f"exposes host device {value}", Severity.MEDIUM
        elif option in {"--volume", "--mount"} and value:
            source = _mount_source(option, value)
            problem = _sensitive_mount(source) if source else None
        elif option == "--user" and value in {"root", "0", "0:0"}:
            problem = "runs as root inside the container", Severity.MEDIUM
        if problem:
            message, severity = problem
            evidence = f"{option} {value}" if value is not None else option
            yield _finding(
                "MCPS205",
                server,
                f"Container {message}",
                server.locate("args"),
                field="args",
                evidence=sanitize(evidence),
                severity=severity,
            )


def _check_broad_fs(server: ServerConfig, launch: Launch) -> Iterator[Finding]:
    if launch.base in DOCKER_LIKE:
        return
    for arg in launch.args:
        candidates = [arg]
        if arg.startswith("-") and "=" in arg:
            candidates.append(arg.split("=", 1)[1])
        for candidate in candidates:
            breadth = path_breadth(candidate)
            if not breadth:
                continue
            what = "the filesystem root" if breadth == "root" else "a home directory"
            yield _finding(
                "MCPS206",
                server,
                f"Server is given access to {what} ({candidate})",
                _arg_location(server, arg),
                field="args",
                evidence=sanitize(arg),
                severity=Severity.HIGH if breadth == "root" else Severity.MEDIUM,
            )
            break


def is_loopback(host: str | None) -> bool:
    """Return whether ``host`` is ``localhost``, a ``*.localhost`` name or a loopback IP."""
    if not host:
        return False
    host = host.lower().strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _plain_http_host(url: str) -> str | None:
    """Return the host of a plain-HTTP URL to a non-loopback host, else None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() != "http":
        return None
    try:
        host = parts.hostname
    except ValueError:
        return None
    return None if is_loopback(host) else (host or "?")


def _check_transport(server: ServerConfig) -> Iterator[Finding]:
    if server.url:
        host = _plain_http_host(server.url)
        if host:
            key = next((k for k in ("url", "serverUrl", "httpUrl") if k in server.raw), "url")
            yield _finding(
                "MCPS207",
                server,
                f"Remote MCP endpoint {host} is reached over plain HTTP",
                server.locate(key),
                field=key,
                evidence=sanitize(server.url),
            )
    for index, arg in enumerate(server.args):
        for url in re.findall(r"\bhttp://[^\s\"']+", arg, flags=re.IGNORECASE):
            host = _plain_http_host(url)
            if host:
                yield _finding(
                    "MCPS207",
                    server,
                    f"Argument points to plain-HTTP endpoint {host}",
                    server.locate("args", index),
                    field=f"args[{index}]",
                    evidence=sanitize(url),
                    severity=Severity.MEDIUM,
                )


_TLS_ENV = {
    "NODE_TLS_REJECT_UNAUTHORIZED": {"0"},
    "PYTHONHTTPSVERIFY": {"0"},
    "GIT_SSL_NO_VERIFY": {"1", "true", "yes"},
    "CURL_CA_BUNDLE": {""},
}
_TLS_ENV_GENERIC = re.compile(r"(?i)(?:ssl|tls)[_-]?(?:verify|verification|check)")
_TLS_FLAGS = frozenset(
    {
        "--insecure",
        "--no-verify-ssl",
        "--no-check-certificate",
        "--ignore-certificate-errors",
        "--allow-insecure",
        "--skip-tls-verify",
        "--tls-skip-verify",
        "--insecure-skip-tls-verify",
        "--disable-ssl-verification",
        "--no-ssl-verify",
        "--ssl-no-verify",
        "--tls-no-verify",
        "--trust-all-certs",
    }
)


def _check_tls(server: ServerConfig) -> Iterator[Finding]:
    for key, value in server.env.items():
        upper, low = key.upper(), value.strip().lower()
        bad = (
            low in _TLS_ENV[upper]
            if upper in _TLS_ENV
            else (bool(_TLS_ENV_GENERIC.search(key)) and low in {"0", "false", "no", "off"})
        )
        if bad:
            yield _finding(
                "MCPS208",
                server,
                f"Environment variable {key}={value!r} disables TLS verification",
                server.locate("env", key),
                field=f"env.{key}",
            )
    for index, arg in enumerate(server.args):
        if arg.split("=", 1)[0].lower() in _TLS_FLAGS:
            yield _finding(
                "MCPS208",
                server,
                f"Flag {arg!r} disables TLS verification",
                server.locate("args", index),
                field=f"args[{index}]",
            )


def _check_auto_approve(server: ServerConfig) -> Iterator[Finding]:
    for key in ("alwaysAllow", "autoApprove", "auto_approve", "always_allow"):
        value = server.raw.get(key)
        if value is True:
            yield _finding(
                "MCPS209",
                server,
                f"All tools of this server run without confirmation ({key}: true)",
                server.locate(key),
                field=key,
                severity=Severity.HIGH,
            )
        elif isinstance(value, list) and value:
            names = [str(v) for v in value]
            risky = [n for n in names if n == "*" or classify_name(n)]
            message = f"{len(names)} tool(s) run without confirmation ({key})"
            if risky:
                message += f"; includes high-impact tools: {', '.join(risky[:5])}"
            yield _finding(
                "MCPS209",
                server,
                message,
                server.locate(key),
                field=key,
                evidence=sanitize(", ".join(names)),
                severity=Severity.HIGH if risky else Severity.MEDIUM,
            )
    if server.raw.get("trust") is True:
        yield _finding(
            "MCPS209",
            server,
            "'trust: true' bypasses every tool-call confirmation for this server",
            server.locate("trust"),
            field="trust",
            severity=Severity.HIGH,
        )


# Variable name -> None (always reported) or a pattern the value must match.
_INJECTION_ENV = {
    "LD_PRELOAD": None,
    "LD_AUDIT": None,
    "DYLD_INSERT_LIBRARIES": None,
    "PYTHONSTARTUP": None,
    "BASH_ENV": None,
    "PERL5OPT": None,
    "PERL5DB": None,
    "NODE_OPTIONS": re.compile(
        r"(?:^|\s)(?:--require|-r|--import|--loader|--experimental-loader|--inspect(?:-brk)?)\b"
    ),
    "RUBYOPT": re.compile(r"(?:^|\s)-r"),
    "JAVA_TOOL_OPTIONS": re.compile(r"-(?:javaagent|agentpath|agentlib)"),
    "_JAVA_OPTIONS": re.compile(r"-(?:javaagent|agentpath|agentlib)"),
    "JDK_JAVA_OPTIONS": re.compile(r"-(?:javaagent|agentpath|agentlib)"),
}


def _check_env_injection(server: ServerConfig) -> Iterator[Finding]:
    for key, value in server.env.items():
        upper = key.upper()
        if upper in _INJECTION_ENV:
            condition = _INJECTION_ENV[upper]
            if condition is None or condition.search(value):
                yield _finding(
                    "MCPS210",
                    server,
                    f"Environment variable {key} loads extra code into the server process",
                    server.locate("env", key),
                    field=f"env.{key}",
                    evidence=sanitize(f"{key}={value}", 160),
                )
        elif upper in {"LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}:
            yield _finding(
                "MCPS210",
                server,
                f"Environment variable {key} changes which shared libraries the server loads",
                server.locate("env", key),
                field=f"env.{key}",
                evidence=sanitize(f"{key}={value}", 160),
                severity=Severity.MEDIUM,
            )


def check_server(server: ServerConfig) -> Iterator[Finding]:
    if server.command:
        launch = analyze_launch(server.command, server.args)
        yield from _check_inline(server, launch)
        yield from _check_remote_exec(server)
        yield from _check_elevation(server, launch)
        yield from _check_unpinned(server, launch)
        yield from _check_container(server, launch)
        yield from _check_broad_fs(server, launch)
    yield from _check_transport(server)
    yield from _check_tls(server)
    yield from _check_auto_approve(server)
    yield from _check_env_injection(server)


def check_document(doc: SourceDocument) -> Iterator[Finding]:
    """Report duplicate keys and global VS Code auto-approval settings."""
    for pointer in doc.duplicates:
        parent, _, key = pointer.rpartition("/")
        key = key.replace("~1", "/").replace("~0", "~")  # Unescape the JSON Pointer token.
        yield Finding(
            get("MCPS001"),
            f"Key {key!r} is defined more than once in {parent or '/'}; "
            "only the last definition takes effect",
            doc.locate(pointer),
            field=pointer,
        )
    data = doc.data if isinstance(doc.data, dict) else {}
    for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
        if data.get(key) is True:
            yield Finding(
                get("MCPS209"),
                f"VS Code setting {key}=true approves every tool call without confirmation",
                doc.locate("/" + key),
                field=key,
                severity=Severity.HIGH,
            )
