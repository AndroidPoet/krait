import type {
  AgentDefinition,
  AgentHandler,
  AgentOutput,
  Probe,
  ProbeAttack,
  ProbeResult,
  ScanResult,
  Trajectory,
} from "../types/index.js";
import { summarizeResults } from "../utils/index.js";

export interface RunnerOptions {
  concurrency: number;
  timeout: number;
  verbose: boolean;
  onProbeStart?: (probe: Probe, attackIndex: number, totalAttacks: number) => void;
  onProbeResult?: (result: ProbeResult) => void;
}

const DEFAULT_OPTIONS: RunnerOptions = {
  concurrency: 1,
  timeout: 30_000,
  verbose: false,
};

/**
 * The scan engine. Takes an agent and a list of probes, runs all attacks,
 * collects results.
 */
export class ScanRunner {
  private options: RunnerOptions;

  constructor(options: Partial<RunnerOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  /** Run all probes against an agent */
  async scan(
    agent: AgentDefinition,
    probes: Probe[]
  ): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const startMs = Date.now();
    const results: ProbeResult[] = [];

    const handler = this.resolveHandler(agent);

    for (const probe of probes) {
      const attacks = probe.generateAttacks(agent);

      for (let i = 0; i < attacks.length; i++) {
        const attack = attacks[i];
        this.options.onProbeStart?.(probe, i + 1, attacks.length);

        try {
          const output = await this.executeAttack(handler, attack);
          const result = probe.evaluate(attack, output);
          results.push(result);
          this.options.onProbeResult?.(result);
        } catch (err) {
          const errorOutput = this.createErrorOutput(err);
          const result: ProbeResult = {
            probeId: probe.id,
            probeName: probe.name,
            category: probe.category,
            severity: probe.severity,
            status: "error",
            finding: `Probe execution error: ${err instanceof Error ? err.message : String(err)}`,
            attack,
            output: errorOutput,
          };
          results.push(result);
          this.options.onProbeResult?.(result);
        }
      }
    }

    const completedAt = new Date().toISOString();
    return {
      agent: agent.name,
      startedAt,
      completedAt,
      durationMs: Date.now() - startMs,
      summary: summarizeResults(results),
      results,
    };
  }

  /** Execute a single attack against the agent handler */
  private async executeAttack(
    handler: AgentHandler,
    attack: ProbeAttack
  ): Promise<AgentOutput> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(
        () => reject(new Error(`Attack timed out after ${this.options.timeout}ms`)),
        this.options.timeout
      );
    });

    return Promise.race([handler(attack.input), timeoutPromise]);
  }

  /** Resolve the agent handler based on provider type */
  private resolveHandler(agent: AgentDefinition): AgentHandler {
    switch (agent.provider.type) {
      case "function":
        return agent.provider.handler;

      case "mock":
        return this.createMockHandler(agent);

      case "http":
        return this.createHttpHandler(agent);

      case "command":
        return this.createCommandHandler(agent);

      default:
        throw new Error(`Unknown provider type: ${(agent.provider as { type: string }).type}`);
    }
  }

  /** Create a handler from mock responses */
  private createMockHandler(agent: AgentDefinition): AgentHandler {
    const provider = agent.provider;
    if (provider.type !== "mock") throw new Error("Not a mock provider");

    return async (input) => {
      // Find matching mock response
      const match = provider.responses.find((r) => {
        if (!r.input) return true; // default response
        if (typeof r.input === "string")
          return input.message.includes(r.input);
        return r.input.test(input.message);
      });

      const response = match || provider.responses[0];
      if (!response) {
        return {
          response: "No mock response configured.",
          trajectory: this.emptyTrajectory(),
        };
      }

      return {
        response: response.output,
        trajectory: {
          steps: response.steps || [],
          totalDurationMs: 0,
          totalTokens: 0,
          totalCostUsd: 0,
        },
      };
    };
  }

  /** Create a handler that calls an HTTP endpoint */
  private createHttpHandler(agent: AgentDefinition): AgentHandler {
    const provider = agent.provider;
    if (provider.type !== "http") throw new Error("Not an HTTP provider");

    return async (input) => {
      const res = await fetch(provider.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...provider.headers,
        },
        body: JSON.stringify(input),
      });

      if (!res.ok) {
        throw new Error(`Agent HTTP error: ${res.status} ${res.statusText}`);
      }

      const data = (await res.json()) as AgentOutput;
      return {
        response: data.response || "",
        trajectory: data.trajectory || this.emptyTrajectory(),
        tokenUsage: data.tokenUsage,
        durationMs: data.durationMs,
      };
    };
  }

  /** Create a handler that runs a shell command */
  private createCommandHandler(agent: AgentDefinition): AgentHandler {
    const provider = agent.provider;
    if (provider.type !== "command") throw new Error("Not a command provider");

    return async (input) => {
      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const execFileAsync = promisify(execFile);

      const args = [...(provider.args || []), JSON.stringify(input)];
      const { stdout, stderr } = await execFileAsync(provider.command, args, {
        timeout: this.options.timeout,
      });

      if (stderr) {
        return {
          response: stderr,
          trajectory: this.emptyTrajectory(),
          error: stderr,
        };
      }

      try {
        return JSON.parse(stdout) as AgentOutput;
      } catch {
        return {
          response: stdout,
          trajectory: this.emptyTrajectory(),
        };
      }
    };
  }

  /** Execute a single attack against an agent (public — used by red team) */
  async runSingleAttack(
    agent: AgentDefinition,
    attack: ProbeAttack
  ): Promise<AgentOutput> {
    const handler = this.resolveHandler(agent);
    return this.executeAttack(handler, attack);
  }

  private emptyTrajectory(): Trajectory {
    return { steps: [], totalDurationMs: 0, totalTokens: 0, totalCostUsd: 0 };
  }

  private createErrorOutput(err: unknown): AgentOutput {
    return {
      response: "",
      trajectory: this.emptyTrajectory(),
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
