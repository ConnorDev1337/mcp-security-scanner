# Real-world tool definitions

Tool definitions (`tools/list` results plus server `instructions`) captured from popular
open-source MCP servers, used to measure and guard against false positives
(`tests/test_real_corpus.py`). Each file is a scanner dump (`--dump-tools` format) holding one
server, exactly as the server returned it; nothing was edited. None of the texts contains
invisible or bidirectional Unicode characters (had one done so, it would be stored as a `\uXXXX`
escape).

## Servers

| File | Package / image | Version | Source | License | Tools |
|---|---|---|---|---|---|
| `filesystem.json` | npm `@modelcontextprotocol/server-filesystem` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 14 |
| `memory.json` | npm `@modelcontextprotocol/server-memory` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 9 |
| `sequential-thinking.json` | npm `@modelcontextprotocol/server-sequential-thinking` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 1 |
| `everything.json` | npm `@modelcontextprotocol/server-everything` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 13 |
| `fetch.json` | PyPI `mcp-server-fetch` | 2026.10.10 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT | 1 |
| `git.json` | PyPI `mcp-server-git` | 2026.10.10 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT | 12 |
| `time.json` | PyPI `mcp-server-time` | 2026.10.10 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT | 2 |
| `github.json` | `ghcr.io/github/github-mcp-server` (2) | v2.0.2 | [github/github-mcp-server](https://github.com/github/github-mcp-server) | MIT | 91 |
| `playwright.json` | npm `@playwright/mcp` (3) | 0.0.83 | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | Apache-2.0 | 45 |
| `context7.json` | npm `@upstash/context7-mcp` | 4.4.2 | [upstash/context7](https://github.com/upstash/context7) | MIT | 2 |
| `notion.json` | npm `@notionhq/notion-mcp-server` | 2.5.2 | [makenotion/notion-mcp-server](https://github.com/makenotion/notion-mcp-server) | MIT | 24 |
| `desktop-commander.json` | npm `@wonderwhy-er/desktop-commander` | 0.3.0 | [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | MIT | 25 |
| `kubernetes.json` | npm `mcp-server-kubernetes` | 4.1.9 | [Flux159/mcp-server-kubernetes](https://github.com/Flux159/mcp-server-kubernetes) | MIT | 23 |
| `grafana.json` | `grafana/mcp-grafana` (4) | 2.0.2 | [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) | Apache-2.0 | 79 |
| `supabase.json` | npm `@supabase/mcp-server-supabase` (5) | 0.14.0 | [supabase-community/supabase-mcp](https://github.com/supabase-community/supabase-mcp) | Apache-2.0 | 31 |

Total: 15 servers, 372 tools, captured on 2026-10-16.

1. The MCP project is relicensing from MIT to Apache-2.0; code is under one or the other
   depending on the contributor (see the repository's `LICENSE`). Both permit redistribution.
2. Image digest `sha256:ffced0d76e77428532a2ced185516992d77fd146d69eec2f244e6237d1a97796`,
   started with `stdio --toolsets all` so every toolset is listed.
3. Started with `--headless --caps vision,pdf,devtools` so the optional tools are listed.
4. Image digest `sha256:78d208116ec52b09b44f0eca66892073b39aefcb64483c54d43255c8eab7e97a`,
   default toolsets. It reports its version as `(devel)`.
5. Started with `--features account,database,debugging,development,functions,branching,storage`:
   the `docs` feature downloads its schema from the network at start-up.

Servers that were tried and left out: `@stripe/mcp` 0.3.3 is only a proxy to Stripe's remote
server and needs a real API key to list tools.

## How the files were produced

All third-party code ran only inside a throwaway Docker container built from pinned images and
packages (`npm install -g --ignore-scripts PACKAGE@VERSION`, `pip install PACKAGE==VERSION` in a
virtual environment, the Go binaries copied from the official images by digest). The container
ran as an unprivileged user with `--network none`; servers that need a token got the placeholder
`placeholder-not-a-real-token`. The scanner itself was mounted read-only and run inside it:

```bash
docker run --rm --network none -v "$PWD/src:/scanner/src:ro" -v "$PWD/out:/out" \
  -v "$PWD/config.json:/work/config.json:ro" -e PYTHONPATH=/scanner/src IMAGE \
  python -m mcp_scanner scan /work/config.json --introspect --timeout 90 \
  --dump-tools /out/dump.json --no-pins --fail-on none
```

The dump was then split into one file per server (UTF-8, LF line endings).

## License notices

The descriptions are redistributed under the licenses of their projects. Copyright notices:

- MCP reference servers: Copyright (c) 2024-2025 Model Context Protocol a Series of LF Projects,
  LLC.; `mcp-server-fetch` and `mcp-server-git`: Copyright (c) 2024 Anthropic, PBC.
- `github-mcp-server`: Copyright (c) 2025 GitHub.
- `@playwright/mcp`: Copyright (c) Microsoft Corporation.
- `@upstash/context7-mcp`: Copyright (c) 2021 Upstash, Inc.
- `@notionhq/notion-mcp-server`: Copyright (c) 2025 Notion Labs, Inc.
- `@wonderwhy-er/desktop-commander`: Copyright (c) 2024-2025 Eduard Ruzga and Desktop Commander
  Contributors.
- `mcp-server-kubernetes`: Copyright (c) 2024 Suyog Sonwalkar.
- `mcp-grafana`: Copyright 2025 Grafana Labs.
- `@supabase/mcp-server-supabase`: Copyright 2025 Supabase.

The Apache License 2.0 text is in this repository's [`LICENSE`](../../../LICENSE). The MIT
License text, which applies to the MIT-licensed files above:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software
> and associated documentation files (the "Software"), to deal in the Software without
> restriction, including without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
> Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
> BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
