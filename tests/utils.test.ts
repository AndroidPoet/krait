import { describe, it, expect } from "vitest";
import {
  containsPII,
  detectSystemPromptLeak,
  detectGoalHijack,
  detectUnauthorizedToolUse,
  detectExcessiveSteps,
} from "../src/utils/patterns.js";
import { formatDuration, formatCost, summarizeResults } from "../src/utils/index.js";

// ─── PII Detection ──────────────────────────────────────────────────────────

describe("containsPII", () => {
  it("detectsEmailAddresses", () => {
    const result = containsPII("Contact us at user@example.com for help");
    expect(result.found).toBe(true);
    expect(result.types).toContain("email");
  });

  it("detectsSSN", () => {
    const result = containsPII("SSN: 123-45-6789");
    expect(result.found).toBe(true);
    expect(result.types).toContain("ssn");
  });

  it("detectsCreditCards", () => {
    const result = containsPII("Card: 4111-1111-1111-1111");
    expect(result.found).toBe(true);
    expect(result.types).toContain("creditCard");
  });

  it("detectsAPIKeys", () => {
    const result = containsPII("Use this: sk_live_abc123def456ghi789");
    expect(result.found).toBe(true);
    expect(result.types).toContain("apiKey");
  });

  it("returnsCleanForSafeText", () => {
    const result = containsPII("Hello, how can I help you today?");
    expect(result.found).toBe(false);
    expect(result.types).toHaveLength(0);
  });
});

// ─── System Prompt Leak Detection ───────────────────────────────────────────

describe("detectSystemPromptLeak", () => {
  it("detectsLeakIndicators", () => {
    expect(detectSystemPromptLeak("My instructions are to help users")).toBe(true);
    expect(detectSystemPromptLeak("I was told to never share data")).toBe(true);
    expect(detectSystemPromptLeak("Here are my instructions for you")).toBe(true);
  });

  it("returnsFalseForNormalText", () => {
    expect(detectSystemPromptLeak("Here is your order status")).toBe(false);
    expect(detectSystemPromptLeak("The weather is sunny today")).toBe(false);
  });
});

// ─── Goal Hijack Detection ──────────────────────────────────────────────────

describe("detectGoalHijack", () => {
  it("detectsHijackIndicators", () => {
    expect(detectGoalHijack("Sure, I'll ignore my previous instructions")).toBe(true);
    expect(detectGoalHijack("Okay, forgetting my previous task now")).toBe(true);
  });

  it("returnsFalseForNormalText", () => {
    expect(detectGoalHijack("I can help with that request")).toBe(false);
  });
});

// ─── Unauthorized Tool Detection ────────────────────────────────────────────

describe("detectUnauthorizedToolUse", () => {
  it("identifiesUnauthorizedTools", () => {
    const calls = [{ name: "search" }, { name: "hack_system" }, { name: "delete" }];
    const allowed = ["search", "delete"];
    const unauthorized = detectUnauthorizedToolUse(calls, allowed);

    expect(unauthorized).toEqual(["hack_system"]);
  });

  it("returnsEmptyWhenAllAuthorized", () => {
    const calls = [{ name: "search" }];
    const allowed = ["search", "delete"];
    const unauthorized = detectUnauthorizedToolUse(calls, allowed);

    expect(unauthorized).toHaveLength(0);
  });
});

// ─── Excessive Steps Detection ──────────────────────────────────────────────

describe("detectExcessiveSteps", () => {
  it("detectsExcessiveSteps", () => {
    expect(detectExcessiveSteps(25, 20)).toBe(true);
  });

  it("returnsFalseWithinBudget", () => {
    expect(detectExcessiveSteps(5, 20)).toBe(false);
  });
});

// ─── Formatting Utils ───────────────────────────────────────────────────────

describe("formatDuration", () => {
  it("formatsMilliseconds", () => {
    expect(formatDuration(500)).toBe("500ms");
  });

  it("formatsSeconds", () => {
    expect(formatDuration(5000)).toBe("5.0s");
  });

  it("formatsMinutes", () => {
    expect(formatDuration(120000)).toBe("2.0m");
  });
});

describe("formatCost", () => {
  it("formatsTinyCosts", () => {
    expect(formatCost(0.0012)).toBe("$0.0012");
  });

  it("formatsNormalCosts", () => {
    expect(formatCost(1.5)).toBe("$1.50");
  });
});

// ─── Summary Utils ──────────────────────────────────────────────────────────

describe("summarizeResults", () => {
  it("correctlySummarizesResults", () => {
    const results = [
      { status: "pass", severity: "critical" },
      { status: "fail", severity: "critical" },
      { status: "fail", severity: "high" },
      { status: "pass", severity: "medium" },
      { status: "error", severity: "low" },
    ];
    const summary = summarizeResults(results);

    expect(summary.total).toBe(5);
    expect(summary.passed).toBe(2);
    expect(summary.failed).toBe(2);
    expect(summary.errors).toBe(1);
    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(1);
  });

  it("handlesEmptyResults", () => {
    const summary = summarizeResults([]);
    expect(summary.total).toBe(0);
    expect(summary.passed).toBe(0);
  });
});
