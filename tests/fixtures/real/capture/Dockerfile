# Throwaway image used only to introspect third-party MCP servers (see ../README.md).
# Network is only available while the image is built; captures run with --network none.
FROM ghcr.io/github/github-mcp-server:v2.0.2@sha256:ffced0d76e77428532a2ced185516992d77fd146d69eec2f244e6237d1a97796 AS github
FROM grafana/mcp-grafana:2.0.2@sha256:78d208116ec52b09b44f0eca66892073b39aefcb64483c54d43255c8eab7e97a AS grafana
FROM hashicorp/terraform-mcp-server:1.3.0@sha256:423a6b8e2ee06affcf090892f40c86469caba45fd2448ffa8ca5d717a174f7d5 AS terraform
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=github /server/github-mcp-server /usr/local/bin/github-mcp-server
RUN npm install -g --ignore-scripts --no-audit --no-fund \
      @modelcontextprotocol/server-filesystem@1.0.0 \
      @modelcontextprotocol/server-memory@1.0.0 \
      @modelcontextprotocol/server-sequential-thinking@1.0.0 \
      @modelcontextprotocol/server-everything@1.0.0 \
      @playwright/mcp@0.0.83 \
      @upstash/context7-mcp@4.4.2 \
      @notionhq/notion-mcp-server@2.5.2 \
      @wonderwhy-er/desktop-commander@0.3.0 \
      mcp-server-kubernetes@4.1.9
COPY --from=grafana /app/mcp-grafana /usr/local/bin/mcp-grafana
RUN npm install -g --ignore-scripts --no-audit --no-fund @supabase/mcp-server-supabase@0.14.0
RUN for p in fetch git time; do \
      python -m venv /opt/$p && /opt/$p/bin/pip install -q --no-cache-dir mcp-server-$p==2026.10.10; \
    done
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && git init -q /repo && mkdir -p /data
# Servers added for prompts and resources, each in its own prefix so their commands cannot clash.
COPY --from=terraform /bin/terraform-mcp-server /usr/local/bin/terraform-mcp-server
RUN for spec in \
      mongodb-mcp-server@3.1.0 \
      @modelcontextprotocol/server-puppeteer@2025.5.12 \
      @heroku/mcp-server@1.2.12 \
      @executeautomation/playwright-mcp-server@1.0.12 \
      @cyanheads/git-mcp-server@2.15.3; do \
      dir="/opt/js/$(echo "${spec%@*}" | tr -d @ | tr / -)"; \
      npm install --prefix "$dir" --ignore-scripts --no-audit --no-fund "$spec" >/dev/null || exit 1; \
    done
# The archived reference servers predate version 2 of the MCP Python SDK.
RUN for spec in mcp-server-sqlite==2025.4.25 mcp-server-sentry==2025.1.14; do \
      dir="/opt/${spec%%==*}"; \
      python -m venv "$dir" && "$dir/bin/pip" install -q --no-cache-dir "$spec" mcp==1.30.0 || exit 1; \
    done
RUN useradd -m scanner
USER scanner
WORKDIR /home/scanner
