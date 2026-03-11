import { Command } from "commander";
import chalk from "chalk";
import { loadConfig } from "../../config/loader.js";
import { ScanRunner } from "../../engine/runner.js";
import { mutateAttacks } from "../../engine/mutator.js";
import {
  generateAttacks,
  batchJudge,
  createProvider,
  autoDetectProvider,
} from "../../redteam/index.js";
import type { ProviderConfig } from "../../redteam/index.js";
import { generateCombinations } from "../../engine/combinator.js";
import { getAllProbes } from "../../probes/index.js";
import type { ProbeAttack, ProbeResult } from "../../types/index.js";

const SEVERITY_BADGE: Record<string, string> = {
  critical: chalk.bgRed.white.bold(" CRIT "),
  high: chalk.bgYellow.black.bold(" HIGH "),
  medium: chalk.bgBlue.white(" MED "),
  low: chalk.bgGray.white(" LOW "),
};

export const redteamCommand = new Command("redteam")
  .description(
    "AI-powered red teaming — generates novel attacks using an LLM and evaluates responses semantically"
  )
  .argument("<config>", "Path to krait config YAML")
  .option(
    "--provider <type>",
    "LLM provider: anthropic, openai, ollama",
    "anthropic"
  )
  .option("--model <model>", "Model to use for attack generation and judging")
  .option("--api-key <key>", "API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY)")
  .option("--base-url <url>", "Custom API base URL")
  .option(
    "--attacks-per-category <n>",
    "Number of attacks per category",
    "3"
  )
  .option("--mutate", "Also run mutation engine on existing attacks", false)
  .option("--mutations <n>", "Max mutations to generate", "50")
  .option("--combine", "Generate attacks from pattern database with permutations", false)
  .option("--combinations <n>", "Max combinations to generate", "200")
  .option("--patterns <file>", "Custom patterns JSON file")
  .option("--judge", "Use LLM judge for evaluation (otherwise uses built-in heuristics)", false)
  .option("--json", "Output as JSON")
  .option("--output <file>", "Write results to file")
  .action(
    async (
      configPath: string,
      opts: {
        provider: string;
        model?: string;
        apiKey?: string;
        baseUrl?: string;
        attacksPerCategory: string;
        mutate: boolean;
        mutations: string;
        combine: boolean;
        combinations: string;
        patterns?: string;
        judge: boolean;
        json?: boolean;
        output?: string;
      }
    ) => {
      const config = await loadConfig(configPath);
      const runner = new ScanRunner({ timeout: config.settings?.timeout || 10000 });

      // Resolve LLM provider
      let providerConfig: ProviderConfig | null = null;

      if (opts.apiKey || opts.model) {
        providerConfig = {
          type: opts.provider as ProviderConfig["type"],
          model: opts.model || (opts.provider === "anthropic" ? "claude-sonnet-4-20250514" : "gpt-4o"),
          apiKey: opts.apiKey,
          baseUrl: opts.baseUrl,
        };
      } else {
        providerConfig = autoDetectProvider();
      }

      if (!providerConfig) {
        console.log(chalk.yellow("\n  No LLM provider configured."));
        console.log(chalk.dim("  Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or use --provider ollama\n"));

        if (!opts.mutate && !opts.combine) {
          console.log(chalk.dim("  Tip: Use --mutate and/or --combine to run without an LLM\n"));
          process.exit(1);
        }
      }

      const llmProvider = providerConfig ? createProvider(providerConfig) : null;

      console.log();
      console.log(
        chalk.bold("━━━ RED TEAM ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
      );

      if (llmProvider) {
        console.log(chalk.dim(`  Provider: ${llmProvider.name}`));
      }

      const allResults: ProbeResult[] = [];

      for (const agent of config.agents) {
        console.log();
        console.log(chalk.bold(`  Agent: ${agent.name}`));
        console.log();

        const novelAttacks: ProbeAttack[] = [];

        // Phase 1: LLM-generated attacks
        if (llmProvider) {
          console.log(chalk.dim("  ⟳ Generating novel attacks with LLM..."));

          try {
            const generated = await generateAttacks(llmProvider, agent, {
              attacksPerCategory: parseInt(opts.attacksPerCategory),
            });
            novelAttacks.push(...generated);
            console.log(
              chalk.green(`  ✓ Generated ${generated.length} novel attacks`)
            );
          } catch (err) {
            console.log(
              chalk.red(
                `  ✗ Attack generation failed: ${err instanceof Error ? err.message : String(err)}`
              )
            );
          }
        }

        // Phase 2: Mutation attacks
        if (opts.mutate) {
          console.log(chalk.dim("  ⟳ Generating mutation variants..."));

          const probes = getAllProbes();
          const existingAttacks = probes.flatMap((p) => p.generateAttacks(agent));
          const mutations = mutateAttacks(existingAttacks, {
            maxTotal: parseInt(opts.mutations),
            maxPerAttack: 2,
          });
          novelAttacks.push(...mutations);
          console.log(
            chalk.green(`  ✓ Generated ${mutations.length} mutation variants`)
          );
        }

        // Phase 2.5: Pattern DB combinations
        if (opts.combine) {
          console.log(chalk.dim("  ⟳ Generating pattern combinations..."));

          try {
            const combinations = generateCombinations(agent, {
              maxAttacks: parseInt(opts.combinations),
              patternsFile: opts.patterns,
              chains: true,
            });
            novelAttacks.push(...combinations);
            console.log(
              chalk.green(
                `  ✓ Generated ${combinations.length} pattern combinations`
              )
            );
          } catch (err) {
            console.log(
              chalk.red(
                `  ✗ Combination generation failed: ${err instanceof Error ? err.message : String(err)}`
              )
            );
          }
        }

        if (novelAttacks.length === 0) {
          console.log(chalk.yellow("  No attacks generated."));
          continue;
        }

        // Phase 3: Execute attacks
        console.log(
          chalk.dim(`  ⟳ Executing ${novelAttacks.length} attacks...`)
        );

        const attackResults: Array<{
          attack: ProbeAttack;
          output: Awaited<ReturnType<typeof runner.runSingleAttack>>;
        }> = [];

        for (const attack of novelAttacks) {
          try {
            const output = await runner.runSingleAttack(agent, attack);
            attackResults.push({ attack, output });
          } catch {
            // Skip failed executions
          }
        }

        console.log(
          chalk.green(`  ✓ Executed ${attackResults.length} attacks`)
        );

        // Phase 4: Evaluate results
        let results: ProbeResult[];

        if (opts.judge && llmProvider) {
          console.log(chalk.dim("  ⟳ LLM judge evaluating responses..."));

          results = await batchJudge(
            llmProvider,
            attackResults.map((r) => ({
              attack: r.attack,
              output: r.output,
            }))
          );
        } else {
          // Use built-in heuristic evaluation
          const probes = getAllProbes();
          results = attackResults.map((r) => {
            const probe = probes.find((p) => p.id === r.attack.probeId);
            if (probe) {
              return probe.evaluate(r.attack, r.output);
            }
            // Default heuristic for unknown categories
            return {
              probeId: r.attack.probeId,
              probeName: "Red Team",
              category: r.attack.probeId as ProbeResult["category"],
              status: "pass" as const,
              severity: "medium" as const,
              finding: "No matching probe for evaluation — manual review recommended",
              attack: r.attack,
              output: r.output,
            };
          });
        }

        allResults.push(...results);

        // Print results
        const passed = results.filter((r) => r.status === "pass");
        const failed = results.filter((r) => r.status === "fail");

        for (const r of failed) {
          const badge = SEVERITY_BADGE[r.severity] || r.severity;
          console.log(`  ${badge} ${chalk.red("✗")} ${r.finding}`);
          if (r.evidence) {
            for (const issue of r.evidence) {
              console.log(chalk.dim(`       → ${issue}`));
            }
          }
        }

        console.log();
        console.log(
          `  ${chalk.green(`${passed.length} passed`)}  ${chalk.red(`${failed.length} failed`)}`
        );
      }

      // Summary
      console.log();
      console.log(
        chalk.bold("━━━ RED TEAM SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
      );
      console.log();

      const totalPassed = allResults.filter((r) => r.status === "pass").length;
      const totalFailed = allResults.filter((r) => r.status === "fail").length;
      const criticalCount = allResults.filter(
        (r) => r.status === "fail" && r.severity === "critical"
      ).length;

      const passRate =
        allResults.length > 0
          ? ((totalPassed / allResults.length) * 100).toFixed(1)
          : "0";

      console.log(`  ${passRate}% pass rate`);
      console.log(
        `  ${totalPassed} passed  ${totalFailed} failed  ${allResults.length} total`
      );
      if (criticalCount > 0) {
        console.log(chalk.red.bold(`  ${criticalCount} CRITICAL findings`));
      }
      console.log();

      // JSON / file output
      if (opts.json) {
        const report = {
          type: "redteam",
          timestamp: new Date().toISOString(),
          provider: llmProvider?.name || "mutation-only",
          results: allResults.map((r) => ({
            probeId: r.probeId,
            status: r.status,
            severity: r.severity,
            intent: r.attack.intent,
            finding: r.finding,
            evidence: r.evidence,
          })),
          summary: {
            total: allResults.length,
            passed: totalPassed,
            failed: totalFailed,
            critical: criticalCount,
          },
        };
        console.log(JSON.stringify(report, null, 2));
      }

      if (opts.output) {
        const { writeFileSync } = await import("fs");
        const report = {
          type: "redteam",
          timestamp: new Date().toISOString(),
          results: allResults.map((r) => ({
            probeId: r.probeId,
            status: r.status,
            severity: r.severity,
            intent: r.attack.intent,
            finding: r.finding,
            evidence: r.evidence || [],
          })),
        };
        writeFileSync(opts.output, JSON.stringify(report, null, 2));
        console.log(chalk.dim(`  Results written to ${opts.output}`));
      }

      if (totalFailed > 0) {
        process.exit(1);
      }
    }
  );
