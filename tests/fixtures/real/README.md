# Real-world tool definitions

Definitions captured from popular open-source MCP servers: `tools/list` results, server
`instructions`, and the results of `prompts/list`, `resources/list` and `resources/templates/list`.
They are used to measure and guard against false positives (`tests/test_real_corpus.py`). Each
file is a scanner dump (`--dump-tools` format) holding one server, exactly as the server returned
it; nothing was edited. Every file has the `prompts`, `resources` and `resourceTemplates` keys: an
empty list means the server does not advertise that capability or lists none. None of the texts
contains invisible or bidirectional Unicode characters (had one done so, it would be stored as a
`\uXXXX` escape), secret-shaped strings or the placeholder tokens given to the servers.

## Servers

| File | Package / image | Version | Source | License | Tools | Prompts | Resources | Templates |
|---|---|---|---|---|---|---|---|---|
| `filesystem.json` | npm `@modelcontextprotocol/server-filesystem` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 14 | 0 | 0 | 0 |
| `memory.json` | npm `@modelcontextprotocol/server-memory` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 9 | 0 | 1 | 0 |
| `sequential-thinking.json` | npm `@modelcontextprotocol/server-sequential-thinking` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 1 | 0 | 0 | 0 |
| `everything.json` | npm `@modelcontextprotocol/server-everything` | 1.0.0 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT / Apache-2.0 (1) | 13 | 4 | 7 | 2 |
| `fetch.json` | PyPI `mcp-server-fetch` | 2026.10.10 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT | 1 | 1 | 0 | 0 |
| `git.json` | PyPI `mcp-server-git` | 2026.10.10 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT | 12 | 0 | 0 | 0 |
| `time.json` | PyPI `mcp-server-time` | 2026.10.10 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MIT | 2 | 0 | 0 | 0 |
| `puppeteer.json` | npm `@modelcontextprotocol/server-puppeteer` (2) | 2025.5.12 | [modelcontextprotocol/servers-archived](https://github.com/modelcontextprotocol/servers-archived) | MIT | 7 | 0 | 1 | 0 |
| `sqlite.json` | PyPI `mcp-server-sqlite` (2) | 2025.4.25 | [modelcontextprotocol/servers-archived](https://github.com/modelcontextprotocol/servers-archived) | MIT | 6 | 1 | 1 | 0 |
| `sentry.json` | PyPI `mcp-server-sentry` (2) | 2025.1.14 | [modelcontextprotocol/servers-archived](https://github.com/modelcontextprotocol/servers-archived) | MIT | 1 | 1 | 0 | 0 |
| `github.json` | `ghcr.io/github/github-mcp-server` (3) | v2.0.2 | [github/github-mcp-server](https://github.com/github/github-mcp-server) | MIT | 91 | 2 | 4 | 5 |
| `playwright.json` | npm `@playwright/mcp` (4) | 0.0.83 | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | Apache-2.0 | 45 | 0 | 0 | 0 |
| `playwright-ea.json` | npm `@executeautomation/playwright-mcp-server` | 1.0.12 | [executeautomation/mcp-playwright](https://github.com/executeautomation/mcp-playwright) | MIT | 33 | 0 | 1 | 0 |
| `context7.json` | npm `@upstash/context7-mcp` | 4.4.2 | [upstash/context7](https://github.com/upstash/context7) | MIT | 2 | 0 | 0 | 0 |
| `notion.json` | npm `@notionhq/notion-mcp-server` | 2.5.2 | [makenotion/notion-mcp-server](https://github.com/makenotion/notion-mcp-server) | MIT | 24 | 0 | 0 | 0 |
| `desktop-commander.json` | npm `@wonderwhy-er/desktop-commander` (5) | 0.3.0 | [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | MIT | 25 | 0 | 2 | 0 |
| `kubernetes.json` | npm `mcp-server-kubernetes` | 4.1.9 | [Flux159/mcp-server-kubernetes](https://github.com/Flux159/mcp-server-kubernetes) | MIT | 23 | 1 | 5 | 0 |
| `grafana.json` | `grafana/mcp-grafana` (6) | 2.0.2 | [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) | Apache-2.0 | 79 | 0 | 2 | 0 |
| `supabase.json` | npm `@supabase/mcp-server-supabase` (7) | 0.14.0 | [supabase-community/supabase-mcp](https://github.com/supabase-community/supabase-mcp) | Apache-2.0 | 31 | 0 | 0 | 0 |
| `terraform.json` | `hashicorp/terraform-mcp-server` (8) | 1.3.0 | [hashicorp/terraform-mcp-server](https://github.com/hashicorp/terraform-mcp-server) | MPL-2.0 | 9 | 0 | 2 | 1 |
| `mongodb.json` | npm `mongodb-mcp-server` (9) | 3.1.0 | [mongodb-js/mongodb-mcp-server](https://github.com/mongodb-js/mongodb-mcp-server) | Apache-2.0 | 27 | 0 | 2 | 1 |
| `heroku.json` | npm `@heroku/mcp-server` | 1.2.12 | [heroku/heroku-mcp-server](https://github.com/heroku/heroku-mcp-server) | Apache-2.0 | 33 | 0 | 1 | 0 |
| `git-cyanheads.json` | npm `@cyanheads/git-mcp-server` | 2.15.3 | [cyanheads/git-mcp-server](https://github.com/cyanheads/git-mcp-server) | Apache-2.0 | 28 | 1 | 1 | 1 |

Total: 23 servers, 516 tools, 11 prompts, 30 resources and 10 resource templates. The first 15
servers were captured on 2026-10-16 with tools only and re-captured on 2026-10-17 with the same
versions and image digests, together with the last eight, which were added for their prompts and
resources.

1. The MCP project is relicensing from MIT to Apache-2.0; code is under one or the other
   depending on the contributor (see the repository's `LICENSE`). Both permit redistribution.
2. Archived reference servers. The Python ones need version 1 of the MCP SDK, so `mcp==1.30.0`
   was installed next to them. `mcp-server-sqlite` ran with `--db-path /tmp/demo.db` (a new,
   empty database) and `mcp-server-sentry` with a placeholder `--auth-token`.
3. Image digest `sha256:ffced0d76e77428532a2ced185516992d77fd146d69eec2f244e6237d1a97796`,
   started with `stdio --toolsets all` so every toolset is listed.
4. Started with `--headless --caps vision,pdf,devtools` so the optional tools are listed.
5. Its tool descriptions embed details of the machine it runs on: the container ID and the list
   of mounted directories. The re-capture changed only those parts of 11 descriptions; the
   findings are the same.
6. Image digest `sha256:78d208116ec52b09b44f0eca66892073b39aefcb64483c54d43255c8eab7e97a`,
   default toolsets. It reports its version as `(devel)`.
7. Started with `--features account,database,debugging,development,functions,branching,storage`:
   the `docs` feature downloads its schema from the network at start-up.
8. Image digest `sha256:423a6b8e2ee06affcf090892f40c86469caba45fd2448ffa8ca5d717a174f7d5`,
   started with `stdio`.
9. Started without a connection string, with telemetry disabled.

Servers that were tried and left out:

- `@stripe/mcp` 0.3.3 is only a proxy to Stripe's remote server and needs a real API key to list
  tools.
- `@sveltejs/mcp` 0.1.26 exits before answering `tools/list` without network access, and
  `@neondatabase/mcp-server-neon` 0.6.5 contacts `console.neon.tech` at start-up.
- `@azure-devops/mcp` 2.10.0 needs a native module (`keytar`) built by an install script, and
  install scripts are not run.
- `mcp-server-docker` 0.3.0 needs a Docker daemon socket at start-up, and
  `@modelcontextprotocol/server-postgres` 0.6.2 needs a reachable database to list its resources.
- `@bytebase/dbhub` 1.5.0 (`--demo`), `next-devtools-mcp` 0.4.0 and `mcp-server-motherduck` 1.1.0
  advertise prompts or resources but list none, so they add nothing to cover.

## Dynamic prompts and resources

`prompts/list` and the resource listings can depend on run-time state. Two captures run one after
the other returned identical prompts, resources and templates for every server, so the files are
deterministic, but a live server may list more:

- `everything` registers a session resource for each file that its `gzip-file-as-resource` tool
  compresses, `mongodb` serves the results of its export tool through the `exported-data://`
  template, and the resource lists of database or file servers follow their data (the postgres
  reference server lists one resource per table).
- Pinning therefore reports a new concrete resource (MCPS408) at LOW severity and a removed one
  (MCPS409) at LOW, while new prompts and resource templates keep MEDIUM. `size` and
  `annotations.lastModified` are not part of a resource's pinned definition, so `grafana`'s
  `size` does not cause MCPS407 when its bundled UI changes size.
- Tests pin the whole corpus and check it again (no finding), and check that one extra session
  resource of `everything` produces exactly one LOW MCPS408, then one LOW MCPS409 once gone.

## How the files were produced

All third-party code ran only inside a throwaway Docker container built from pinned images and
packages ([`capture/Dockerfile`](capture/Dockerfile): `npm install --ignore-scripts
PACKAGE@VERSION`, `pip install PACKAGE==VERSION` in a virtual environment, the Go binaries copied
from the official images by digest). Network access was only available while the image was built.
The container ran as an unprivileged user with `--network none`; servers that need a token got the
placeholder `placeholder-not-a-real-token`, and no real account was used. The scanner itself was
mounted read-only and run inside it with the client configuration
[`capture/servers.json`](capture/servers.json):

```bash
docker build -t mcp-corpus tests/fixtures/real/capture
docker run --rm --network none -v "$PWD/src:/scanner/src:ro" -v "$PWD/out:/out" \
  -v "$PWD/tests/fixtures/real/capture/servers.json:/work/config.json:ro" \
  -e PYTHONPATH=/scanner/src mcp-corpus \
  python -m mcp_scanner scan /work/config.json --introspect --timeout 90 \
  --dump-tools /out/dump.json --no-pins --fail-on none
PYTHONPATH=src python tests/fixtures/real/capture/split.py out/dump.json tests/fixtures/real
```

`--introspect` calls only listing methods (`tools/list`, and `prompts/list`, `resources/list` and
`resources/templates/list` when advertised); no prompt was rendered and no resource was read.
[`capture/split.py`](capture/split.py) writes one file per server (UTF-8, LF line endings) and
escapes hidden characters.

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
- Archived reference servers (`@modelcontextprotocol/server-puppeteer`, `mcp-server-sqlite`,
  `mcp-server-sentry`): Copyright (c) 2024 Anthropic, PBC.
- `@executeautomation/playwright-mcp-server`: Copyright (c) 2025 ExecuteAutomation.
- `terraform-mcp-server`: Copyright (c) 2025 HashiCorp, Inc. Licensed under the Mozilla Public
  License 2.0 (<https://mozilla.org/MPL/2.0/>); its source code is available from the repository
  linked above.
- `mongodb-mcp-server`: MongoDB, Inc. (its `LICENSE` carries no copyright line; the author in
  `package.json` is MongoDB).
- `@heroku/mcp-server`: Copyright (c) 2025 Heroku.
- `@cyanheads/git-mcp-server`: Copyright 2026 Casey Hand @cyanheads.

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
