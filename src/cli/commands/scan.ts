import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/index.js";
import { ScanRunner } from "../../engine/index.js";
import { getAllProbes, getProbesByCategory } from "../../probes/index.js";
import {
  printBanner,
  printReport,
} from "../../reporters/index.js";
import { writeJsonReport } from "../../reporters/json.js";
import { writeHtmlReport } from "../../reporters/html.js";
import { summarizeResults } from "../../utils/index.js";
import type { ProbeCategory, ScanReport, ScanResult } from "../../types/index.js";

export const scanCommand = new Command("scan")
  .description("Run security probes against your AI agents")
  .argument("[config]", "Path to krait config file", "krait.yaml")
  .option("-p, --probes <probes>", "Comma-separated probe categories to run")
  .option("-a, --agent <name>", "Run probes against a specific agent only")
  .option("-o, --output <file>", "Write report to file (JSON or HTML based on extension)")
  .option("-v, --verbose", "Show detailed findings and evidence", false)
  .option("--timeout <ms>", "Timeout per probe in milliseconds", "30000")
  .option("--concurrency <n>", "Number of concurrent probe executions", "1")
  .action(async (configPath: string, options) => {
    printBanner();

    // Load config
    const spinner = ora("Loading configuration...").start();
    let config;
    try {
      config = await loadConfig(configPath);
      spinner.succeed(`Loaded ${config.agents.length} agent(s) from ${configPath}`);
    } catch (err) {
      spinner.fail(
        `Failed to load config: ${err instanceof Error ? err.message : String(err)}`
      );
      process.exit(1);
    }

    // Resolve probes
    let probes;
    if (options.probes) {
      const categories = options.probes.split(",") as ProbeCategory[];
      probes = getProbesByCategory(categories);
      if (probes.length === 0) {
        console.error(chalk.red(`No probes found for categories: ${options.probes}`));
        process.exit(1);
      }
    } else if (config.probes) {
      probes = getProbesByCategory(config.probes);
    } else {
      probes = getAllProbes();
    }

    console.log(
      chalk.dim(`  Running ${probes.length} probe(s) × ${config.agents.length} agent(s)\n`)
    );

    // Filter agents
    const agents = options.agent
      ? config.agents.filter((a) => a.name === options.agent)
      : config.agents;

    if (agents.length === 0) {
      console.error(chalk.red(`No agent found with name: ${options.agent}`));
      process.exit(1);
    }

    // Run scans
    const runner = new ScanRunner({
      timeout: parseInt(options.timeout, 10),
      concurrency: parseInt(options.concurrency, 10),
      verbose: options.verbose,
      onProbeStart: (probe, idx, total) => {
        if (options.verbose) {
          console.log(
            chalk.dim(`  [${idx}/${total}] ${probe.name}: running...`)
          );
        }
      },
    });

    const agentResults: ScanResult[] = [];

    for (const agent of agents) {
      const agentSpinner = ora(`Scanning agent: ${agent.name}`).start();
      try {
        const result = await runner.scan(agent, probes);
        agentResults.push(result);
        const { passed, failed } = result.summary;
        if (failed > 0) {
          agentSpinner.warn(
            `${agent.name}: ${passed} passed, ${chalk.red.bold(`${failed} failed`)}`
          );
        } else {
          agentSpinner.succeed(`${agent.name}: ${chalk.green.bold(`${passed} passed`)}`);
        }
      } catch (err) {
        agentSpinner.fail(
          `${agent.name}: scan error — ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Build report
    const allResults = agentResults.flatMap((r) => r.results);
    const report: ScanReport = {
      version: "0.1.0",
      timestamp: new Date().toISOString(),
      agents: agentResults,
      overallSummary: summarizeResults(allResults),
    };

    // Print report
    printReport(report, options.verbose);

    // Write output file if requested
    if (options.output) {
      const outputSpinner = ora(`Writing report to ${options.output}`).start();
      try {
        if (options.output.endsWith(".html")) {
          await writeHtmlReport(report, options.output);
        } else {
          await writeJsonReport(report, options.output);
        }
        outputSpinner.succeed(`Report written to ${options.output}`);
      } catch (err) {
        outputSpinner.fail(
          `Failed to write report: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Exit with non-zero if any failures
    if (report.overallSummary.failed > 0 || report.overallSummary.critical > 0) {
      process.exit(1);
    }
  });
