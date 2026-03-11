#!/usr/bin/env node

import { Command } from "commander";
import { scanCommand } from "./cli/commands/scan.js";
import { initCommand } from "./cli/commands/init.js";
import { listCommand } from "./cli/commands/list.js";
import { auditCommand } from "./cli/commands/audit.js";
import { redteamCommand } from "./cli/commands/redteam.js";
import { watchCommand } from "./cli/commands/watch.js";
import { mcpCommand } from "./cli/commands/mcp.js";
import { autoCommand } from "./cli/commands/auto.js";

const program = new Command()
  .name("krait")
  .description(
    "🐍 krait — Security testing for AI agents\n\nStop shipping agents that hallucinate, loop, and leak."
  )
  .version("0.2.0");

program.addCommand(scanCommand);
program.addCommand(initCommand);
program.addCommand(listCommand);
program.addCommand(auditCommand);
program.addCommand(redteamCommand);
program.addCommand(watchCommand);
program.addCommand(mcpCommand);
program.addCommand(autoCommand);

program.parse();
