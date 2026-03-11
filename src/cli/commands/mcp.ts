import { Command } from "commander";
import { startMcpServer } from "../../mcp/server.js";

export const mcpCommand = new Command("mcp")
  .description(
    "Start krait as an MCP server — adds security advisor tools to Claude Code, Cursor, etc."
  )
  .action(async () => {
    await startMcpServer();
  });
