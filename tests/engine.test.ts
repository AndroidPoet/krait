import { describe, it, expect } from "vitest";
import type { AgentDefinition, AgentOutput } from "../src/types/index.js";
import { ScanRunner } from "../src/engine/runner.js";
import { evaluateAssertions } from "../src/engine/assertions.js";
import { getAllProbes } from "../src/probes/index.js";

// ─── Test Helpers ───────────────────────────────────────────────────────────

const mockAgent: AgentDefinition = {
  name: "test-agent",
  provider: {
    type: "mock",
    responses: [
      { output: "I can help with that.", steps: [] },
      { input: "HIJACKED", output: "I cannot follow those instructions.", steps: [] },
    ],
  },
  tools: [
    { name: "search", description: "Search" },
    { name: "delete", description: "Delete records", destructive: true },
  ],
};

// ─── ScanRunner ─────────────────────────────────────────────────────────────

describe("ScanRunner", () => {
  it("scan_runsAllProbesAgainstAgent", async () => {
    const runner = new ScanRunner({ timeout: 5000 });
    const probes = getAllProbes();
    const result = await runner.scan(mockAgent, probes);

    expect(result.agent).toBe("test-agent");
    expect(result.results.length).toBeGreaterThan(0);
    expect(result.summary.total).toBe(result.results.length);
    expect(result.summary.passed + result.summary.failed + result.summary.errors + result.summary.skipped)
      .toBe(result.summary.total);
  });

  it("scan_producesValidSummary", async () => {
    const runner = new ScanRunner({ timeout: 5000 });
    const probes = getAllProbes().slice(0, 2); // just two probes for speed
    const result = await runner.scan(mockAgent, probes);

    expect(result.summary).toHaveProperty("total");
    expect(result.summary).toHaveProperty("passed");
    expect(result.summary).toHaveProperty("failed");
    expect(result.summary).toHaveProperty("critical");
    expect(result.summary).toHaveProperty("high");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.startedAt).toBeTruthy();
    expect(result.completedAt).toBeTruthy();
  });

  it("scan_handlesEmptyProbeList", async () => {
    const runner = new ScanRunner();
    const result = await runner.scan(mockAgent, []);

    expect(result.results).toHaveLength(0);
    expect(result.summary.total).toBe(0);
  });
});

// ─── Assertions ─────────────────────────────────────────────────────────────

describe("Assertions", () => {
  const baseOutput: AgentOutput = {
    response: "Here is your order status.",
    trajectory: {
      steps: [
        {
          index: 0,
          type: "tool_call",
          content: "Calling search",
          toolCall: { name: "search", arguments: { query: "order 123" } },
          timestampMs: Date.now(),
        },
        {
          index: 1,
          type: "tool_result",
          content: "Found order",
          toolResult: { name: "search", output: "Order 123: shipped", durationMs: 50 },
          timestampMs: Date.now(),
        },
      ],
      totalDurationMs: 200,
      totalTokens: 300,
      totalCostUsd: 0.005,
    },
  };

  it("tool_called_passesWhenToolWasCalled", () => {
    const results = evaluateAssertions(
      [{ type: "tool_called", value: "search" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("tool_called_failsWhenToolNotCalled", () => {
    const results = evaluateAssertions(
      [{ type: "tool_called", value: "delete" }],
      baseOutput
    );
    expect(results[0].passed).toBe(false);
  });

  it("tool_not_called_passesWhenToolAbsent", () => {
    const results = evaluateAssertions(
      [{ type: "tool_not_called", value: "delete" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("tool_not_called_failsWhenToolPresent", () => {
    const results = evaluateAssertions(
      [{ type: "tool_not_called", value: "search" }],
      baseOutput
    );
    expect(results[0].passed).toBe(false);
  });

  it("output_contains_matchesCaseInsensitive", () => {
    const results = evaluateAssertions(
      [{ type: "output_contains", value: "ORDER STATUS" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("output_not_contains_passesWhenAbsent", () => {
    const results = evaluateAssertions(
      [{ type: "output_not_contains", value: "error" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("output_matches_worksWithRegexString", () => {
    const results = evaluateAssertions(
      [{ type: "output_matches", value: "order.*status" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("steps_under_passesWhenUnderLimit", () => {
    const results = evaluateAssertions(
      [{ type: "steps_under", value: 10 }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("steps_under_failsWhenOverLimit", () => {
    const results = evaluateAssertions(
      [{ type: "steps_under", value: 1 }],
      baseOutput
    );
    expect(results[0].passed).toBe(false);
  });

  it("cost_under_passesWhenCheap", () => {
    const results = evaluateAssertions(
      [{ type: "cost_under", value: 1.0 }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("no_sensitive_data_passesWhenClean", () => {
    const results = evaluateAssertions(
      [{ type: "no_sensitive_data", value: "" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("no_sensitive_data_failsWhenPIIPresent", () => {
    const outputWithPII: AgentOutput = {
      ...baseOutput,
      response: "User email: john@example.com, SSN: 123-45-6789",
    };
    const results = evaluateAssertions(
      [{ type: "no_sensitive_data", value: "" }],
      outputWithPII
    );
    expect(results[0].passed).toBe(false);
  });

  it("no_tool_errors_passesWhenNoErrors", () => {
    const results = evaluateAssertions(
      [{ type: "no_tool_errors", value: "" }],
      baseOutput
    );
    expect(results[0].passed).toBe(true);
  });

  it("no_tool_errors_failsWhenErrorPresent", () => {
    const outputWithError: AgentOutput = {
      ...baseOutput,
      trajectory: {
        ...baseOutput.trajectory,
        steps: [
          ...baseOutput.trajectory.steps,
          {
            index: 2,
            type: "tool_result",
            content: "Error",
            toolResult: { name: "search", output: null, error: "Connection refused", durationMs: 0 },
            timestampMs: Date.now(),
          },
        ],
      },
    };
    const results = evaluateAssertions(
      [{ type: "no_tool_errors", value: "" }],
      outputWithError
    );
    expect(results[0].passed).toBe(false);
  });
});
