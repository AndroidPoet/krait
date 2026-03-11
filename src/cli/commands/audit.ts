import { Command } from "commander";
import chalk from "chalk";
import { loadConfig } from "../../config/loader.js";
import { auditAgents } from "../../engine/auditor.js";
import type { AuditFinding } from "../../engine/auditor.js";

const SEVERITY_BADGE: Record<string, string> = {
  critical: chalk.bgRed.white.bold(" CRITICAL "),
  high: chalk.bgYellow.black.bold(" HIGH "),
  medium: chalk.bgBlue.white(" MEDIUM "),
  low: chalk.bgGray.white(" LOW "),
};

export const auditCommand = new Command("audit")
  .description(
    "Static analysis of agent configs — finds dangerous patterns without running probes"
  )
  .argument("<config>", "Path to krait config YAML")
  .option("--json", "Output as JSON")
  .action(async (configPath: string, opts: { json?: boolean }) => {
    const config = await loadConfig(configPath);
    const findings = auditAgents(config.agents);

    if (opts.json) {
      console.log(JSON.stringify(findings, null, 2));
      return;
    }

    console.log();
    console.log(
      chalk.bold("━━━ CONFIG AUDIT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    );
    console.log();

    if (findings.length === 0) {
      console.log(chalk.green.bold("  ✓ No configuration issues found."));
      console.log();
      return;
    }

    // Group by agent
    const byAgent = new Map<string, AuditFinding[]>();
    for (const f of findings) {
      const existing = byAgent.get(f.agent) || [];
      existing.push(f);
      byAgent.set(f.agent, existing);
    }

    for (const [agent, agentFindings] of byAgent) {
      console.log(chalk.bold(`  Agent: ${agent}`));
      console.log();

      for (const f of agentFindings) {
        const badge = SEVERITY_BADGE[f.severity] || f.severity;
        console.log(`  ${badge} ${f.rule}`);
        console.log(`    ${chalk.dim("Issue:")} ${f.message}`);
        console.log(`    ${chalk.dim("Fix:")} ${f.remediation}`);
        console.log();
      }
    }

    // Summary
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;

    console.log(chalk.bold("━━━ AUDIT SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
    console.log();
    console.log(`  ${chalk.bold(findings.length.toString())} issues found`);
    if (critical > 0) console.log(`  ${chalk.red.bold(`${critical} CRITICAL`)}`);
    if (high > 0) console.log(`  ${chalk.yellow.bold(`${high} HIGH`)}`);
    if (medium > 0) console.log(`  ${chalk.blue(`${medium} MEDIUM`)}`);
    console.log();

    if (critical > 0) {
      process.exit(1);
    }
  });
