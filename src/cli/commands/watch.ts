import { Command } from "commander";
import chalk from "chalk";
import { watch } from "fs";
import { resolve, dirname } from "path";
import { loadConfig } from "../../config/loader.js";
import { ScanRunner } from "../../engine/runner.js";
import { auditAgents } from "../../engine/auditor.js";
import { getAllProbes, getProbesByCategory } from "../../probes/index.js";
import type { ProbeCategory } from "../../types/index.js";

export const watchCommand = new Command("watch")
  .description(
    "Watch mode — re-scans automatically when config or agent files change"
  )
  .argument("<config>", "Path to krait config YAML")
  .option("--probes <probes>", "Comma-separated probe categories to run")
  .option("--debounce <ms>", "Debounce delay in ms", "2000")
  .option("--audit", "Also run config audit on each change", false)
  .action(
    async (
      configPath: string,
      opts: { probes?: string; debounce: string; audit: boolean }
    ) => {
      const absPath = resolve(configPath);
      const watchDir = dirname(absPath);
      const debounceMs = parseInt(opts.debounce);

      console.log();
      console.log(
        chalk.bold("━━━ WATCH MODE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
      );
      console.log(chalk.dim(`  Watching: ${watchDir}`));
      console.log(chalk.dim(`  Config: ${absPath}`));
      console.log(chalk.dim(`  Debounce: ${debounceMs}ms`));
      console.log(chalk.dim(`  Press Ctrl+C to stop`));
      console.log();

      // Run initial scan
      await runScan(absPath, opts);

      // Watch for changes
      let timeout: ReturnType<typeof setTimeout> | null = null;
      let scanning = false;

      const watcher = watch(
        watchDir,
        { recursive: true },
        (_event, filename) => {
          if (!filename) return;
          // Skip node_modules, dist, .git
          if (
            filename.includes("node_modules") ||
            filename.includes("dist") ||
            filename.includes(".git")
          ) {
            return;
          }

          // Only trigger on relevant files
          const relevant =
            filename.endsWith(".yaml") ||
            filename.endsWith(".yml") ||
            filename.endsWith(".js") ||
            filename.endsWith(".ts") ||
            filename.endsWith(".json");

          if (!relevant) return;

          if (timeout) clearTimeout(timeout);
          timeout = setTimeout(async () => {
            if (scanning) return;
            scanning = true;

            console.log();
            console.log(
              chalk.yellow(`  ⟳ Change detected: ${filename}`)
            );

            try {
              await runScan(absPath, opts);
            } catch (err) {
              console.log(
                chalk.red(
                  `  ✗ Scan failed: ${err instanceof Error ? err.message : String(err)}`
                )
              );
            }

            scanning = false;
          }, debounceMs);
        }
      );

      // Handle graceful shutdown
      process.on("SIGINT", () => {
        watcher.close();
        console.log(chalk.dim("\n  Watch stopped."));
        process.exit(0);
      });

      // Keep process alive
      await new Promise(() => {});
    }
  );

async function runScan(
  configPath: string,
  opts: { probes?: string; audit: boolean }
) {
  const timestamp = new Date().toLocaleTimeString();
  console.log(chalk.dim(`  ─── Scan at ${timestamp} ───`));

  const config = await loadConfig(configPath);
  const runner = new ScanRunner({
    timeout: config.settings?.timeout || 10000,
  });

  // Config audit
  if (opts.audit) {
    const findings = auditAgents(config.agents);
    if (findings.length > 0) {
      console.log(
        chalk.yellow(`  ⚠ ${findings.length} config issues found`)
      );
      for (const f of findings) {
        const color = f.severity === "critical" ? chalk.red : chalk.yellow;
        console.log(color(`    ${f.severity.toUpperCase()} ${f.rule}: ${f.message}`));
      }
    }
  }

  // Resolve probes
  let probes;
  if (opts.probes) {
    const categories = opts.probes.split(",") as ProbeCategory[];
    probes = getProbesByCategory(categories);
  } else {
    probes = getAllProbes();
  }

  // Run scan per agent
  for (const agent of config.agents) {
    const result = await runner.scan(agent, probes);

    const { passed, failed, critical, high } = result.summary;
    const total = passed + failed;

    if (failed === 0) {
      console.log(
        chalk.green(`  ✓ ${agent.name}: ${total}/${total} passed (${result.durationMs}ms)`)
      );
    } else {
      console.log(
        chalk.red(
          `  ✗ ${agent.name}: ${failed} failed (${critical} critical, ${high} high)`
        )
      );

      // Show first 3 failures
      const failures = result.results
        .filter((r) => r.status === "fail")
        .slice(0, 3);

      for (const f of failures) {
        console.log(
          chalk.dim(`    → ${f.finding}`)
        );
      }

      if (failed > 3) {
        console.log(chalk.dim(`    → ...and ${failed - 3} more`));
      }
    }
  }
}
