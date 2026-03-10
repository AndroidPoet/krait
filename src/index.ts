#!/usr/bin/env node

import { Command } from "commander";
import { scanCommand } from "./cli/commands/scan.js";
import { initCommand } from "./cli/commands/init.js";
import { listCommand } from "./cli/commands/list.js";

const program = new Command()
  .name("krait")
  .description(
    "🐍 krait — Security testing for AI agents\n\nStop shipping agents that hallucinate, loop, and leak."
  )
  .version("0.1.0");

program.addCommand(scanCommand);
program.addCommand(initCommand);
program.addCommand(listCommand);

program.parse();
