import { Command } from "commander";
import chalk from "chalk";
import { listProbes } from "../../probes/index.js";

const SEVERITY_COLORS: Record<string, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

export const listCommand = new Command("list")
  .description("List all available security probes")
  .action(() => {
    const probes = listProbes();

    console.log(
      chalk.bold(`\n  🐍 Available Security Probes (${probes.length})\n`)
    );

    for (const probe of probes) {
      const sev = SEVERITY_COLORS[probe.severity]?.(
        `[${probe.severity.toUpperCase()}]`
      ) || `[${probe.severity}]`;

      console.log(`  ${sev} ${chalk.bold(probe.name)}`);
      console.log(chalk.dim(`       Category: ${probe.category}  |  ID: ${probe.id}`));
      console.log();
    }

    console.log(
      chalk.dim(
        `  Run specific probes: ${chalk.cyan("krait scan --probes goal-hijacking,tool-misuse")}\n`
      )
    );
  });
