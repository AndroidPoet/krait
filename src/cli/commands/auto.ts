import { Command } from "commander";
import chalk from "chalk";
import { detectAgents } from "../../engine/detector.js";
import { gradeAgent, badgeMarkdown } from "../../engine/grader.js";
import { auditAgents } from "../../engine/auditor.js";
import { loadConfig } from "../../config/loader.js";
import { ScanRunner } from "../../engine/runner.js";
import { getAllProbes } from "../../probes/index.js";
import type { ScanResult, ScanSummary, ProbeResult } from "../../types/index.js";

const GRADE_COLORS: Record<string, (s: string) => string> = {
  "A+": chalk.green.bold,
  A: chalk.green,
  B: chalk.blue,
  C: chalk.yellow,
  D: chalk.red,
  F: chalk.bgRed.white.bold,
};

export const autoCommand = new Command("auto")
  .description(
    "Auto-detect agent framework, scan, audit, and grade — zero config"
  )
  .argument("[dir]", "Project directory to scan", ".")
  .option("--config <file>", "Use a config file instead of auto-detection")
  .option("--json", "Output as JSON")
  .option("--badge", "Output shields.io badge markdown")
  .action(
    async (
      dir: string,
      opts: { config?: string; json?: boolean; badge?: boolean }
    ) => {
      console.log();
      console.log(
        chalk.bold("━━━ KRAIT AUTO ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
      );
      console.log();

      // Step 1: Detect or load config
      let config;

      if (opts.config) {
        config = await loadConfig(opts.config);
        console.log(chalk.dim(`  Config: ${opts.config}`));
      } else {
        console.log(chalk.dim("  Detecting agent framework..."));
        const detection = detectAgents(dir);

        if (detection.agents.length === 0) {
          console.log(
            chalk.yellow(
              "  No agent framework detected. Use --config to specify a config file."
            )
          );
          console.log();
          console.log(chalk.dim("  Supported frameworks:"));
          console.log(
            chalk.dim(
              "    LangChain, CrewAI, OpenAI Assistants, Vercel AI SDK,"
            )
          );
          console.log(
            chalk.dim("    AutoGen, Semantic Kernel, Mastra")
          );
          console.log();
          console.log(chalk.dim("  Or generate a config:"));
          console.log(chalk.dim("    krait auto --config krait.yml"));
          console.log();
          return;
        }

        console.log(
          chalk.green(
            `  Detected: ${detection.framework} (${detection.agents.length} agent${detection.agents.length > 1 ? "s" : ""})`
          )
        );

        for (const agent of detection.agents) {
          console.log(
            chalk.dim(
              `    ${agent.name}: ${agent.tools.length} tools, ${agent.files.length} files (${(agent.confidence * 100).toFixed(0)}% confidence)`
            )
          );
        }

        // Convert detected agents to config format
        config = {
          version: "1" as const,
          agents: detection.agents.map((a) => ({
            name: a.name,
            description: a.description,
            provider: {
              type: "http" as const,
              endpoint: "http://localhost:3000/agent",
            },
            tools: a.tools,
            maxSteps: 15,
            maxCost: 0.5,
          })),
          settings: { timeout: 10000 },
        };
      }

      // Step 2: Audit
      console.log();
      console.log(chalk.dim("  Running config audit..."));
      const auditFindings = auditAgents(config.agents);
      const criticalAudits = auditFindings.filter(
        (f) => f.severity === "critical"
      );
      const highAudits = auditFindings.filter((f) => f.severity === "high");

      if (auditFindings.length > 0) {
        console.log(
          chalk.yellow(
            `  ${auditFindings.length} audit findings (${criticalAudits.length} critical, ${highAudits.length} high)`
          )
        );
      } else {
        console.log(chalk.green("  Config audit: clean"));
      }

      // Step 3: Grade (based on audit alone if no scan endpoint)
      console.log();
      console.log(chalk.dim("  Computing security grade..."));

      // Create a synthetic scan result from audit findings for grading
      const syntheticSummary: ScanSummary = {
        total: auditFindings.length,
        passed: 0,
        failed: auditFindings.length,
        errors: 0,
        skipped: 0,
        critical: criticalAudits.length,
        high: highAudits.length,
        medium: auditFindings.filter((f) => f.severity === "medium").length,
        low: auditFindings.filter((f) => f.severity === "low").length,
      };

      const now = new Date().toISOString();
      const syntheticResult: ScanResult = {
        agent: config.agents[0]?.name || "unknown",
        startedAt: now,
        completedAt: now,
        durationMs: 0,
        results: [],
        summary: syntheticSummary,
      };

      const grade = gradeAgent(syntheticResult, auditFindings);
      const colorFn = GRADE_COLORS[grade.grade] || chalk.gray;

      console.log();
      console.log(
        `  Security Grade: ${colorFn(` ${grade.grade} `)}  (${grade.score}/100)`
      );
      console.log();

      // Breakdown
      console.log(chalk.dim("  Score breakdown:"));
      console.log(chalk.dim(`    Base score:       100`));
      if (grade.breakdown.criticalPenalty > 0)
        console.log(
          chalk.red(
            `    Critical penalty: -${grade.breakdown.criticalPenalty}`
          )
        );
      if (grade.breakdown.highPenalty > 0)
        console.log(
          chalk.yellow(`    High penalty:     -${grade.breakdown.highPenalty}`)
        );
      if (grade.breakdown.mediumPenalty > 0)
        console.log(
          chalk.blue(`    Medium penalty:   -${grade.breakdown.mediumPenalty}`)
        );
      if (grade.breakdown.lowPenalty > 0)
        console.log(
          chalk.dim(`    Low penalty:      -${grade.breakdown.lowPenalty}`)
        );
      if (grade.breakdown.auditPenalty > 0)
        console.log(
          chalk.red(`    Audit penalty:    -${grade.breakdown.auditPenalty}`)
        );
      if (grade.breakdown.bonuses > 0)
        console.log(
          chalk.green(`    Bonuses:          +${grade.breakdown.bonuses}`)
        );
      console.log(chalk.bold(`    Final:            ${grade.score}`));

      // Recommendations
      if (grade.recommendations.length > 0) {
        console.log();
        console.log(chalk.bold("  Recommendations:"));
        for (const rec of grade.recommendations) {
          console.log(chalk.dim(`    → ${rec}`));
        }
      }

      // Badge
      if (opts.badge) {
        console.log();
        console.log(chalk.dim("  Badge markdown:"));
        console.log(`    ${badgeMarkdown(grade)}`);
      }

      // JSON output
      if (opts.json) {
        const report = {
          type: "auto",
          timestamp: new Date().toISOString(),
          framework: config.agents[0]?.description || null,
          agents: config.agents.map((a) => ({
            name: a.name,
            tools: a.tools.length,
          })),
          audit: {
            total: auditFindings.length,
            critical: criticalAudits.length,
            high: highAudits.length,
            findings: auditFindings,
          },
          grade: {
            score: grade.score,
            grade: grade.grade,
            breakdown: grade.breakdown,
            recommendations: grade.recommendations,
          },
        };
        console.log();
        console.log(JSON.stringify(report, null, 2));
      }

      console.log();
    }
  );
