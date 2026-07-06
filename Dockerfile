# Heimdall's MCP server (the `scan_mcp_server` tool) over stdio.
# Used by Glama to build, start, and introspect the server; also runnable directly:
#   docker build -t heimdall-mcp . && docker run --rm -i heimdall-mcp
FROM node:22-slim

# git + CA certs so real scans (GitHub/PyPI targets) work; npm/tar ship with the base image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install the published scanner; the `heimdall-mcp` bin is the stdio MCP server.
RUN npm install -g mcp-heimdall-scan@latest

# The server speaks JSON-RPC over stdio (respond to initialize / tools/list / tools/call).
ENTRYPOINT ["heimdall-mcp"]
