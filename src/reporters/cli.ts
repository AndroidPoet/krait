import chalk from "chalk";
import type { ProbeResult, ScanReport, ScanResult, ScanSummary } from "../types/index.js";
import { formatDuration } from "../utils/index.js";

const SEVERITY_COLORS = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

const STATUS_ICONS = {
  pass: chalk.green("✓"),
  fail: chalk.red("✗"),
  error: chalk.yellow("⚠"),
  skip: chalk.gray("○"),
};

/** Print the krait banner */
export function printBanner(): void {
  console.log(
    chalk.bold(`
  ${chalk.red("🐍 krait")} — security testing for AI agents
  ${chalk.dim("Stop shipping agents that hallucinate, loop, and leak.")}
`)
  );
}

/** Print a single probe result */
export function printProbeResult(result: ProbeResult, verbose = false): void {
  const icon = STATUS_ICONS[result.status];
  const severity = SEVERITY_COLORS[result.severity](`[${result.severity.toUpperCase()}]`);

  console.log(
    `  ${icon} ${severity} ${chalk.bold(result.probeName)} — ${result.finding}`
  );

  if (verbose && result.evidence && result.evidence.length > 0) {
    for (const e of result.evidence) {
      console.log(chalk.dim(`      → ${e}`));
    }
  }

  if (verbose && result.remediation && result.status === "fail") {
    console.log(chalk.cyan(`      💡 ${result.remediation}`));
  }
}

/** Print results for one agent */
export function printAgentResult(result: ScanResult, verbose = false): void {
  console.log(
    `\n${chalk.bold.underline(`Agent: ${result.agent}`)} ${chalk.dim(`(${formatDuration(result.durationMs)})`)}`
  );
  console.log();

  // Group by category
  const grouped = new Map<string, ProbeResult[]>();
  for (const r of result.results) {
    const existing = grouped.get(r.category) || [];
    existing.push(r);
    grouped.set(r.category, existing);
  }

  for (const [category, results] of grouped) {
    const failed = results.filter((r) => r.status === "fail").length;
    const categoryColor = failed > 0 ? chalk.red : chalk.green;
    console.log(
      `  ${categoryColor.bold(category.toUpperCase())} ${chalk.dim(`(${results.length} tests, ${failed} failed)`)}`
    );

    for (const r of results) {
      printProbeResult(r, verbose);
    }
    console.log();
  }
}

/** Print the summary dashboard */
export function printSummary(summary: ScanSummary): void {
  console.log(chalk.bold("\n━━━ SCAN SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
  console.log();

  const total = summary.total;
  const passRate = total > 0 ? ((summary.passed / total) * 100).toFixed(1) : "0";

  // Pass rate bar
  const barWidth = 40;
  const filledWidth = Math.round((summary.passed / Math.max(total, 1)) * barWidth);
  const bar =
    chalk.green("█".repeat(filledWidth)) +
    chalk.red("█".repeat(barWidth - filledWidth));

  console.log(`  ${bar} ${passRate}% passed`);
  console.log();

  console.log(
    `  ${chalk.green.bold(`${summary.passed} passed`)}  ${chalk.red.bold(`${summary.failed} failed`)}  ${chalk.yellow(`${summary.errors} errors`)}  ${chalk.gray(`${summary.skipped} skipped`)}  ${chalk.dim(`${total} total`)}`
  );
  console.log();

  if (summary.critical > 0) {
    console.log(
      SEVERITY_COLORS.critical(
        `  ⚠ ${summary.critical} CRITICAL vulnerabilities found`
      )
    );
  }
  if (summary.high > 0) {
    console.log(
      SEVERITY_COLORS.high(`  ⚠ ${summary.high} HIGH severity issues found`)
    );
  }
  if (summary.medium > 0) {
    console.log(
      SEVERITY_COLORS.medium(
        `  ⚠ ${summary.medium} MEDIUM severity issues found`
      )
    );
  }
  if (summary.low > 0) {
    console.log(
      SEVERITY_COLORS.low(`  ℹ ${summary.low} LOW severity issues found`)
    );
  }

  if (summary.failed === 0 && summary.errors === 0) {
    console.log(chalk.green.bold("\n  ✓ All security probes passed!"));
  }

  console.log();
}

/** Print full scan report */
export function printReport(report: ScanReport, verbose = false): void {
  printBanner();

  for (const agentResult of report.agents) {
    printAgentResult(agentResult, verbose);
  }

  printSummary(report.overallSummary);
}
