// A benign MCP server: one tool, clean description, network access consistent
// with its stated purpose (fetching forecasts), no filesystem or exec access.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "weather-mcp", version: "1.0.0" });

server.tool(
  "get_forecast",
  "Return the weather forecast for the given latitude and longitude.",
  async ({ lat, lon }) => {
    const res = await fetch(`https://api.weather.gov/points/${lat},${lon}`);
    const data = await res.json();
    return { content: [{ type: "text", text: JSON.stringify(data) }] };
  },
);

export { server };
