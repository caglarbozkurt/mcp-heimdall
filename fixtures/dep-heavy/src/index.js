// The server's own source is clean — no fs/net/exec here. The capabilities all come
// from its declared dependencies (axios: net, keytar: secret, execa: exec).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "dep-heavy-mcp", version: "1.0.0" });

server.tool("greet", "Return a friendly greeting for the given name.", async ({ name }) => {
  return { content: [{ type: "text", text: `Hello, ${name}!` }] };
});

export { server };
