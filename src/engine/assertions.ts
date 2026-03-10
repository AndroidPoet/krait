import type {
  Assertion,
  AssertionResult,
  AgentOutput,
} from "../types/index.js";
import { containsPII } from "../utils/patterns.js";

/**
 * Evaluates assertions against an agent's output.
 * Assertions are user-defined rules that check trajectory properties.
 */
export function evaluateAssertions(
  assertions: Assertion[],
  output: AgentOutput
): AssertionResult[] {
  return assertions.map((assertion) => evaluateOne(assertion, output));
}

function evaluateOne(assertion: Assertion, output: AgentOutput): AssertionResult {
  switch (assertion.type) {
    case "tool_called":
      return assertToolCalled(assertion, output);
    case "tool_not_called":
      return assertToolNotCalled(assertion, output);
    case "output_contains":
      return assertOutputContains(assertion, output);
    case "output_not_contains":
      return assertOutputNotContains(assertion, output);
    case "output_matches":
      return assertOutputMatches(assertion, output);
    case "steps_under":
      return assertStepsUnder(assertion, output);
    case "cost_under":
      return assertCostUnder(assertion, output);
    case "no_sensitive_data":
      return assertNoSensitiveData(assertion, output);
    case "no_tool_errors":
      return assertNoToolErrors(assertion, output);
    default:
      return {
        assertion,
        passed: false,
        actual: "unknown",
        message: `Unknown assertion type: ${assertion.type}`,
      };
  }
}

function assertToolCalled(assertion: Assertion, output: AgentOutput): AssertionResult {
  const toolName = String(assertion.value);
  const called = output.trajectory.steps.some(
    (s) => s.type === "tool_call" && s.toolCall?.name === toolName
  );
  return {
    assertion,
    passed: called,
    actual: called ? toolName : "not called",
    message: called
      ? `Tool "${toolName}" was called as expected`
      : `Expected tool "${toolName}" to be called, but it wasn't`,
  };
}

function assertToolNotCalled(assertion: Assertion, output: AgentOutput): AssertionResult {
  const toolName = String(assertion.value);
  const called = output.trajectory.steps.some(
    (s) => s.type === "tool_call" && s.toolCall?.name === toolName
  );
  return {
    assertion,
    passed: !called,
    actual: called ? toolName : "not called",
    message: called
      ? `Tool "${toolName}" was called but should not have been`
      : `Tool "${toolName}" was correctly not called`,
  };
}

function assertOutputContains(assertion: Assertion, output: AgentOutput): AssertionResult {
  const needle = String(assertion.value).toLowerCase();
  const found = output.response.toLowerCase().includes(needle);
  return {
    assertion,
    passed: found,
    actual: found ? "found" : "not found",
    message: found
      ? `Output contains "${assertion.value}"`
      : `Expected output to contain "${assertion.value}", but it doesn't`,
  };
}

function assertOutputNotContains(assertion: Assertion, output: AgentOutput): AssertionResult {
  const needle = String(assertion.value).toLowerCase();
  const found = output.response.toLowerCase().includes(needle);
  return {
    assertion,
    passed: !found,
    actual: found ? "found" : "not found",
    message: found
      ? `Output contains "${assertion.value}" but should not`
      : `Output correctly does not contain "${assertion.value}"`,
  };
}

function assertOutputMatches(assertion: Assertion, output: AgentOutput): AssertionResult {
  const pattern =
    assertion.value instanceof RegExp
      ? assertion.value
      : new RegExp(String(assertion.value), "i");
  const matches = pattern.test(output.response);
  return {
    assertion,
    passed: matches,
    actual: matches ? "matched" : "no match",
    message: matches
      ? `Output matches pattern ${pattern}`
      : `Expected output to match ${pattern}, but it doesn't`,
  };
}

function assertStepsUnder(assertion: Assertion, output: AgentOutput): AssertionResult {
  const max = Number(assertion.value);
  const actual = output.trajectory.steps.length;
  return {
    assertion,
    passed: actual < max,
    actual,
    message:
      actual < max
        ? `Steps (${actual}) under limit (${max})`
        : `Steps (${actual}) exceeded limit (${max})`,
  };
}

function assertCostUnder(assertion: Assertion, output: AgentOutput): AssertionResult {
  const max = Number(assertion.value);
  const actual = output.trajectory.totalCostUsd;
  return {
    assertion,
    passed: actual < max,
    actual,
    message:
      actual < max
        ? `Cost ($${actual.toFixed(4)}) under limit ($${max})`
        : `Cost ($${actual.toFixed(4)}) exceeded limit ($${max})`,
  };
}

function assertNoSensitiveData(
  assertion: Assertion,
  output: AgentOutput
): AssertionResult {
  const piiCheck = containsPII(output.response);
  return {
    assertion,
    passed: !piiCheck.found,
    actual: piiCheck.found ? piiCheck.types.join(", ") : "clean",
    message: piiCheck.found
      ? `Sensitive data found in output: ${piiCheck.types.join(", ")}`
      : "No sensitive data detected in output",
  };
}

function assertNoToolErrors(assertion: Assertion, output: AgentOutput): AssertionResult {
  const errors = output.trajectory.steps.filter(
    (s) => s.type === "tool_result" && s.toolResult?.error
  );
  return {
    assertion,
    passed: errors.length === 0,
    actual: errors.length === 0 ? "no errors" : `${errors.length} errors`,
    message:
      errors.length === 0
        ? "No tool errors detected"
        : `${errors.length} tool error(s) detected`,
  };
}
