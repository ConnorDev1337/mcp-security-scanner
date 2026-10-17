"""Rule catalog: stable identifiers, default severities and remediation text.

Identifiers are part of the public interface (SARIF ``ruleId``, suppression
lists, pin files) and must never be reused for a different check.
"""

from __future__ import annotations

from ..models import Rule, Severity

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_RULES: tuple[Rule, ...] = (
    # ------------------------------------------------------------ configuration
    Rule(
        "MCPS001",
        "config-duplicate-key",
        "Duplicate key in configuration file",
        M,
        "configuration",
        "The same key appears more than once in a JSON object. Parsers keep only the last "
        "value, so a reviewer can read one server definition while the client runs another.",
        "Remove the duplicate entry and keep a single definition per key.",
    ),
    # ------------------------------------------------------------ tool poisoning
    Rule(
        "MCPS101",
        "prompt-injection-markup",
        "Prompt-injection markup in tool metadata",
        H,
        "tool-poisoning",
        "Tool metadata contains tags or chat-template tokens (<IMPORTANT>, <SYSTEM>, [INST], "
        "<|im_start|>) aimed at the language model rather than at a human reader. This is the "
        "most common carrier for tool-poisoning payloads.",
        "Do not connect the server until the text is reviewed. Tool metadata should describe "
        "the tool; it should not contain role markers or emphasis tags addressed to the model.",
    ),
    Rule(
        "MCPS102",
        "instruction-override",
        "Instruction-override phrasing",
        H,
        "tool-poisoning",
        "Text tries to override the agent's existing instructions ('ignore previous "
        "instructions', 'you are now ...', 'new instructions:').",
        "Treat the server as malicious or compromised: remove it and report it to the "
        "maintainer or registry.",
    ),
    Rule(
        "MCPS103",
        "concealment-from-user",
        "Instruction to hide behaviour from the user",
        C,
        "tool-poisoning",
        "The text asks the model to keep actions secret ('do not tell the user', 'without "
        "informing the user', 'secretly'). Legitimate tools have no reason to request secrecy; "
        "this is a hallmark of tool poisoning.",
        "Do not use the server. Remove it from every client configuration and rotate any "
        "credentials the agent could reach while it was connected.",
    ),
    Rule(
        "MCPS104",
        "sensitive-data-reference",
        "Reference to sensitive files or credentials",
        H,
        "tool-poisoning",
        "Tool metadata mentions SSH keys, cloud credentials, MCP client configuration files or "
        "other secrets, or asks the model to read/pass credentials. Poisoned tools use this to "
        "make the agent collect secrets and send them as tool arguments.",
        "Confirm why the tool needs this data. A tool should never ask the model to read "
        "unrelated files or to pass credentials through its arguments.",
    ),
    Rule(
        "MCPS105",
        "exfiltration-instruction",
        "Possible data-exfiltration channel",
        H,
        "tool-poisoning",
        "Metadata instructs the model to send data to a URL, to copy conversation history or "
        "the system prompt into an argument, references known exfiltration endpoints, or "
        "contains download-and-execute commands.",
        "Block the server and inspect what data could have been sent. Arguments should carry "
        "only the data the tool needs for its documented purpose.",
    ),
    Rule(
        "MCPS106",
        "cross-tool-shadowing",
        "Cross-tool shadowing",
        H,
        "tool-poisoning",
        "A tool tries to change how other tools behave ('when this tool is available, the "
        "send_email tool must ...'), references tools of another server, or reuses another "
        "server's tool name. A malicious server can hijack trusted tools this way without "
        "ever being called.",
        "Isolate untrusted servers in a separate agent or session and review any description "
        "that talks about other tools.",
    ),
    Rule(
        "MCPS107",
        "hidden-content",
        "Content hidden from human reviewers",
        M,
        "tool-poisoning",
        "HTML comments, CSS-hidden markup or large whitespace padding hide part of the text "
        "from interfaces that render or truncate it, while the model still receives all of it.",
        "Review the raw text (e.g. with --format json) and remove hidden content.",
    ),
    Rule(
        "MCPS108",
        "model-directed-imperative",
        "Imperative text addressed to the model",
        L,
        "tool-poisoning",
        "The description gives orders to the AI ('the assistant must', 'it is very important "
        "that you', 'before using this tool you must'). Not necessarily malicious, but it is "
        "the steering language tool poisoning relies on.",
        "Review manually. Prefer descriptions that state what the tool does, not how the model "
        "must behave.",
    ),
    Rule(
        "MCPS109",
        "obfuscated-payload",
        "Encoded or obfuscated payload",
        M,
        "tool-poisoning",
        "The text contains an encoded blob (e.g. base64) that decodes to readable text. "
        "Encoding hides instructions from reviewers and from keyword filters.",
        "Decode and review the payload; descriptions have no reason to embed encoded text.",
    ),
    Rule(
        "MCPS110",
        "oversized-description",
        "Unusually long tool description",
        L,
        "tool-poisoning",
        "Very long descriptions are rarely read in full and are often truncated in approval "
        "dialogs, which makes them a convenient place to hide instructions.",
        "Read the full description before approving the tool.",
    ),
    Rule(
        "MCPS120",
        "invisible-unicode",
        "Invisible or deceptive Unicode characters",
        H,
        "tool-poisoning",
        "Zero-width characters, bidirectional controls (Trojan Source), Unicode tag characters "
        "or variation-selector sequences are invisible in most interfaces but are read by the "
        "model. Tag characters and variation selectors can smuggle entire hidden instructions "
        "('ASCII smuggling').",
        "Reject metadata containing invisible characters; the decoded payload, if any, is shown "
        "in the evidence.",
    ),
    Rule(
        "MCPS121",
        "control-characters",
        "Terminal control characters",
        H,
        "tool-poisoning",
        "ANSI escape sequences and other control characters can rewrite, recolour or hide text "
        "when the metadata is printed in a terminal (for example in CLI approval prompts).",
        "Reject metadata containing control characters.",
    ),
    Rule(
        "MCPS122",
        "confusable-identifier",
        "Non-ASCII or mixed-script identifier",
        M,
        "tool-poisoning",
        "A tool, parameter or server name contains non-ASCII letters (e.g. a Cyrillic 'а' in "
        "'reаd_file') that can impersonate a trusted name.",
        "Use ASCII identifiers ([A-Za-z0-9_.-]) as recommended by the MCP specification.",
    ),
    # ------------------------------------------------------------ permissions
    Rule(
        "MCPS201",
        "inline-shell-command",
        "Server launched through a shell or inline code",
        H,
        "permissions",
        "The server is started through a shell (sh -c, cmd /c, powershell -Command) or an "
        "interpreter running inline code (python -c, node -e). The real command is hidden in a "
        "string, metacharacters allow chaining, and encoded commands cannot be reviewed.",
        "Launch the server binary directly with an explicit argument list.",
    ),
    Rule(
        "MCPS202",
        "remote-script-execution",
        "Download-and-execute in launch command",
        C,
        "permissions",
        "The launch command pipes remote content into an interpreter (curl ... | sh, "
        "iwr ... | iex). Whatever the remote host serves is executed with your privileges "
        "every time the client starts.",
        "Install a reviewed, pinned release and launch it locally.",
    ),
    Rule(
        "MCPS203",
        "elevated-privileges",
        "Server runs with elevated privileges",
        H,
        "permissions",
        "The server is launched through sudo, doas, pkexec, runas or gsudo, so a compromised or "
        "manipulated server acts as an administrator.",
        "Run MCP servers as an unprivileged user; grant only the specific access they need.",
    ),
    Rule(
        "MCPS204",
        "unpinned-package",
        "Unpinned package or container image",
        M,
        "permissions",
        "npx/uvx/pipx/docker fetch whatever version is current when the client starts. A "
        "malicious or compromised update (rug pull) runs automatically, without review.",
        "Pin an exact version (pkg@1.2.3, pkg==1.2.3) or an image digest (@sha256:...).",
    ),
    Rule(
        "MCPS205",
        "privileged-container",
        "Container with host-level privileges",
        H,
        "permissions",
        "The container runs privileged, shares host namespaces, mounts the Docker socket or "
        "the host root/home directory, or adds kernel capabilities, so the sandbox no longer "
        "protects the host.",
        "Drop --privileged/host namespaces/capabilities and mount only the directories the "
        "server needs, read-only where possible.",
    ),
    Rule(
        "MCPS206",
        "broad-filesystem-access",
        "Filesystem access to root or home directory",
        M,
        "permissions",
        "The server is given the filesystem root or a home directory, which includes SSH keys, "
        "cloud credentials and other MCP client configurations.",
        "Restrict the server to the project directories it actually needs.",
    ),
    Rule(
        "MCPS207",
        "insecure-transport",
        "Remote server over unencrypted HTTP",
        H,
        "permissions",
        "A remote MCP endpoint is reached over plain http://. Tool definitions, results and any "
        "Authorization header can be read or modified in transit.",
        "Use https:// for every non-loopback endpoint.",
    ),
    Rule(
        "MCPS208",
        "tls-verification-disabled",
        "TLS certificate verification disabled",
        H,
        "permissions",
        "Environment variables or flags (NODE_TLS_REJECT_UNAUTHORIZED=0, --insecure, ...) "
        "disable certificate checks, enabling man-in-the-middle attacks.",
        "Remove the override; install the internal CA certificate instead if needed.",
    ),
    Rule(
        "MCPS209",
        "auto-approval",
        "Tool calls auto-approved",
        M,
        "permissions",
        "alwaysAllow/autoApprove lists or 'trust: true' remove the human confirmation step, so "
        "a poisoned or manipulated tool call executes without anyone seeing it.",
        "Keep confirmation enabled at least for tools that write, delete, execute or send data.",
    ),
    Rule(
        "MCPS210",
        "process-injection-env",
        "Environment variable that injects code into the server",
        H,
        "permissions",
        "Variables such as LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS=--require or "
        "PYTHONSTARTUP load extra code into the server process; in a shared configuration this "
        "is a stealthy way to run arbitrary code.",
        "Remove the variable unless you wrote it and understand exactly what it loads.",
    ),
    Rule(
        "MCPS211",
        "high-risk-tool-capability",
        "High-impact tool capability",
        M,
        "permissions",
        "The tool executes commands or code, deletes/overwrites data, or moves money. Any prompt "
        "injection reaching the agent can trigger it.",
        "Require human confirmation for this tool and restrict what it can reach.",
    ),
    Rule(
        "MCPS212",
        "misleading-tool-annotations",
        "Tool annotations contradict tool behaviour",
        H,
        "permissions",
        "The tool declares readOnlyHint/destructiveHint values that contradict its name or "
        "description. Clients may auto-approve 'read-only' tools, so false hints bypass review.",
        "Treat annotations from untrusted servers as untrusted; fix or remove the hints.",
    ),
    Rule(
        "MCPS213",
        "unconstrained-code-parameter",
        "Free-form code or command parameter",
        M,
        "permissions",
        "A parameter accepts arbitrary commands, code or SQL without enum/pattern constraints, "
        "turning any prompt injection into code execution.",
        "Constrain the parameter (allow-list, pattern) or require confirmation for every call.",
    ),
    Rule(
        "MCPS214",
        "sensitive-resource",
        "Resource points at sensitive local data",
        H,
        "permissions",
        "A resource or resource template URI references credentials or other sensitive local "
        "files (SSH keys, cloud credentials, MCP client configurations, .env files, shell "
        "history, /etc/shadow, browser or keychain stores). Hosts may attach resources to the "
        "model context or let the model pick them, so the secret can end up in the "
        "conversation and in any later tool call without the user noticing.",
        "Do not expose credential files as resources. Restrict the server's resource roots to "
        "the project data it needs and remove the server if it was not meant to publish them.",
    ),
    # ------------------------------------------------------------ secrets
    Rule(
        "MCPS301",
        "hardcoded-secret",
        "Hard-coded API token or private key",
        C,
        "secrets",
        "A value matches the format of a provider credential (GitHub, AWS, OpenAI, Anthropic, "
        "Slack, Stripe, private keys, ...). Configuration files get synced, backed up, shared "
        "in screenshots and read by other local tools and servers.",
        "Rotate the credential now, then reference it from the environment or a secret store "
        "(${VAR}, ${input:...}, OS keychain) instead of writing it in the file.",
    ),
    Rule(
        "MCPS302",
        "hardcoded-credential",
        "Hard-coded credential",
        H,
        "secrets",
        "A credential-like key (TOKEN, PASSWORD, API_KEY, Authorization ...) or command-line "
        "flag holds a literal value. Command-line values are also visible to every local user "
        "through the process list.",
        "Move the value to an environment variable or secret store and rotate it if the file "
        "was ever shared.",
    ),
    Rule(
        "MCPS303",
        "credential-in-url",
        "Credentials embedded in URL",
        H,
        "secrets",
        "A URL contains a password (user:pass@host) or a token in its query string. URLs end up "
        "in logs, proxies and error messages.",
        "Pass credentials in headers sourced from environment variables or a secret store.",
    ),
    Rule(
        "MCPS304",
        "secret-in-pin-file",
        "Credential stored in the pin file",
        H,
        "secrets",
        "The pin file holds a credential in clear text. Pin files written before format 3 "
        "stored tool definitions and server instructions verbatim, including any token or "
        "URL password a server embedded in them, and pin files are meant to be committed. "
        "The scanner rewrites the file without them unless --frozen-pins is set, but "
        "earlier copies (git history, forks, CI caches) keep them.",
        "Rotate the credentials, then commit the rewritten pin file (run once without "
        "--frozen-pins). Removing them from git history does not undo the exposure.",
    ),
    # ------------------------------------------------------------ integrity (pinning)
    Rule(
        "MCPS401",
        "tool-definition-changed",
        "Tool definition changed since approval",
        H,
        "integrity",
        "The hash of the tool definition differs from the approved pin. Servers can change a "
        "tool's description after it was reviewed (rug pull) to inject new instructions.",
        "Review the diff. If the change is legitimate, approve it with --update-pins.",
    ),
    Rule(
        "MCPS402",
        "unapproved-tool",
        "Tool or server not in the approved pin set",
        M,
        "integrity",
        "A tool appeared on an already-approved server, or (with --frozen-pins) a server/tool "
        "has never been approved.",
        "Review the new tool and approve it with --update-pins.",
    ),
    Rule(
        "MCPS403",
        "tool-removed",
        "Approved tool no longer present",
        L,
        "integrity",
        "A previously approved tool disappeared. Usually harmless, but it may accompany a "
        "renamed (and modified) replacement.",
        "Confirm the removal and refresh the pins with --update-pins.",
    ),
    Rule(
        "MCPS404",
        "server-launch-changed",
        "Server launch configuration changed since approval",
        M,
        "integrity",
        "The command, arguments, URL or set of environment variables of a pinned server "
        "changed (values of environment variables are not hashed).",
        "Review the configuration change and approve it with --update-pins.",
    ),
    Rule(
        "MCPS405",
        "server-instructions-changed",
        "Server instructions changed since approval",
        H,
        "integrity",
        "The 'instructions' returned by the server at initialization changed. They are injected "
        "into the model's context, so they deserve the same review as tool descriptions.",
        "Review the diff and approve it with --update-pins.",
    ),
    Rule(
        "MCPS406",
        "prompt-definition-changed",
        "Prompt definition changed since approval",
        H,
        "integrity",
        "The hash of a prompt's listing metadata (name, title, description, arguments) differs "
        "from the approved pin. Prompt templates reach the model when the user invokes them, "
        "so a changed description or argument text can carry new instructions (rug pull).",
        "Review the diff. If the change is legitimate, approve it with --update-pins.",
    ),
    Rule(
        "MCPS407",
        "resource-definition-changed",
        "Resource definition changed since approval",
        H,
        "integrity",
        "The metadata of a resource or resource template (name, title, description, MIME type, "
        "annotations) differs from the approved pin. Resources are identified by URI, so a "
        "changed URI appears as a new resource instead. Size and last-modified time are not "
        "pinned because they follow the content.",
        "Review the diff. If the change is legitimate, approve it with --update-pins.",
    ),
    Rule(
        "MCPS408",
        "unapproved-prompt-or-resource",
        "Prompt or resource not in the approved pin set",
        M,
        "integrity",
        "A prompt, resource or resource template appeared on an already-approved server, or "
        "(with --frozen-pins) the prompts or resources of a server have never been approved, "
        "for example after upgrading from a pin file that predates them. New concrete "
        "resources are reported as low severity because resource lists are often dynamic.",
        "Review the new prompt or resource and approve it with --update-pins.",
    ),
    Rule(
        "MCPS409",
        "prompt-or-resource-removed",
        "Approved prompt or resource no longer present",
        L,
        "integrity",
        "A previously approved prompt, resource or resource template disappeared. Usually "
        "harmless, but it may accompany a renamed (and modified) replacement.",
        "Confirm the removal and refresh the pins with --update-pins.",
    ),
)

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]


def all_rules() -> list[Rule]:
    return list(_RULES)
