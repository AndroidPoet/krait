import { Command } from "commander";
import { writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import chalk from "chalk";
import ora from "ora";

const EXAMPLE_CONFIG = `# krait.yaml — Security testing for AI agents
# Docs: https://github.com/krait-dev/krait

version: "1"

settings:
  concurrency: 1
  timeout: 30000
  verbose: false

agents:
  - name: "my-agent"
    description: "A helpful assistant agent"
    provider:
      type: mock
      responses:
        - output: "I'd be happy to help with that request."
    tools:
      - name: search
        description: "Search the knowledge base"
        sensitive: false
        destructive: false
      - name: send_email
        description: "Send an email to a user"
        destructive: true
      - name: delete_record
        description: "Delete a database record"
        destructive: true
        permissions:
          - admin
      - name: get_user_data
        description: "Retrieve user profile data"
        sensitive: true
    maxSteps: 10
    maxCost: 0.50

# Run specific probe categories (omit to run all):
# probes:
#   - goal-hijacking
#   - tool-misuse
#   - privilege-escalation
#   - data-exfiltration
#   - prompt-injection
#   - excessive-agency
#   - unbounded-consumption
`;

export const initCommand = new Command("init")
  .description("Create a starter krait.yaml config file")
  .option("-f, --force", "Overwrite existing config", false)
  .action(async (options) => {
    const configPath = "krait.yaml";

    if (existsSync(configPath) && !options.force) {
      console.log(
        chalk.yellow(
          `  ${configPath} already exists. Use --force to overwrite.`
        )
      );
      return;
    }

    const spinner = ora("Creating krait.yaml...").start();
    await writeFile(configPath, EXAMPLE_CONFIG, "utf-8");
    spinner.succeed("Created krait.yaml");

    console.log(`
  ${chalk.bold("Next steps:")}
  ${chalk.dim("1.")} Edit krait.yaml to configure your agent
  ${chalk.dim("2.")} Run ${chalk.cyan("krait scan")} to test your agent
  ${chalk.dim("3.")} Run ${chalk.cyan("krait scan --verbose")} for detailed findings
  ${chalk.dim("4.")} Run ${chalk.cyan("krait scan -o report.html")} for an HTML report
`);
  });
