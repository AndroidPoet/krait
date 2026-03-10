// ─── Core Types ─────────────────────────────────────────────────────────────
// Every type in krait flows from these definitions.
// An agent has tools. A probe attacks the agent. A trajectory records what happened.
// An assertion judges whether the trajectory is safe.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ProbeCategory =
  | "goal-hijacking"        // OWASP ASI01
  | "tool-misuse"           // OWASP ASI02
  | "privilege-escalation"  // OWASP ASI03
  | "data-exfiltration"     // OWASP ASI04
  | "prompt-injection"      // OWASP LLM01
  | "excessive-agency"      // OWASP LLM06
  | "cascading-failure"     // OWASP ASI08
  | "system-prompt-leak"    // OWASP LLM07
  | "rogue-behavior"        // OWASP ASI10
  | "unbounded-consumption" // OWASP LLM10
  | "custom";

export type ProbeStatus = "pass" | "fail" | "error" | "skip";

// ─── Agent Definition ───────────────────────────────────────────────────────

export interface ToolDefinition {
  name: string;
  description: string;
  /** If true, this tool can cause side effects (send email, delete data, etc.) */
  destructive?: boolean;
  /** If true, this tool accesses sensitive data */
  sensitive?: boolean;
  /** Permissions required to use this tool */
  permissions?: string[];
  /** Mock response for testing */
  mock?: unknown;
}

export interface AgentDefinition {
  name: string;
  description?: string;
  /** How to invoke the agent — currently supports "function" and "http" */
  provider: AgentProvider;
  /** Tools the agent has access to */
  tools: ToolDefinition[];
  /** System prompt (if accessible — used for prompt leak testing) */
  systemPrompt?: string;
  /** Maximum allowed steps per run */
  maxSteps?: number;
  /** Maximum allowed cost per run (USD) */
  maxCost?: number;
}

export type AgentProvider =
  | { type: "function"; handler: AgentHandler }
  | { type: "http"; endpoint: string; headers?: Record<string, string> }
  | { type: "command"; command: string; args?: string[] }
  | { type: "mock"; responses: MockResponse[] };

export interface MockResponse {
  input?: string | RegExp;
  toolCalls?: ToolCall[];
  output: string;
  steps?: TrajectoryStep[];
}

// ─── Agent Interaction ──────────────────────────────────────────────────────

export interface AgentInput {
  message: string;
  context?: Record<string, unknown>;
}

export interface AgentOutput {
  response: string;
  trajectory: Trajectory;
  tokenUsage?: TokenUsage;
  durationMs?: number;
  error?: string;
}

export type AgentHandler = (input: AgentInput) => Promise<AgentOutput>;

export interface TokenUsage {
  prompt: number;
  completion: number;
  total: number;
}

// ─── Trajectory ─────────────────────────────────────────────────────────────
// The full trace of what an agent did during a run.

export interface Trajectory {
  steps: TrajectoryStep[];
  totalDurationMs: number;
  totalTokens: number;
  totalCostUsd: number;
}

export interface TrajectoryStep {
  index: number;
  type: "thought" | "tool_call" | "tool_result" | "response" | "error";
  content: string;
  toolCall?: ToolCall;
  toolResult?: ToolResult;
  timestampMs: number;
  tokenUsage?: TokenUsage;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolResult {
  name: string;
  output: unknown;
  error?: string;
  durationMs: number;
}

// ─── Probes ─────────────────────────────────────────────────────────────────
// A probe is a single security test. It generates attack inputs and judges results.

export interface Probe {
  id: string;
  name: string;
  description: string;
  category: ProbeCategory;
  severity: Severity;
  /** OWASP reference ID */
  owaspRef?: string;
  /** Generate attack payloads for this probe */
  generateAttacks(agent: AgentDefinition): ProbeAttack[];
  /** Evaluate the agent's response to an attack */
  evaluate(attack: ProbeAttack, output: AgentOutput): ProbeResult;
}

export interface ProbeAttack {
  probeId: string;
  input: AgentInput;
  /** What this specific attack tests */
  intent: string;
  /** Expected safe behavior */
  expectedBehavior: string;
}

export interface ProbeResult {
  probeId: string;
  probeName: string;
  category: ProbeCategory;
  severity: Severity;
  status: ProbeStatus;
  /** Human-readable explanation of the result */
  finding: string;
  /** The attack that was used */
  attack: ProbeAttack;
  /** The agent's actual response */
  output: AgentOutput;
  /** Evidence supporting the finding */
  evidence?: string[];
  /** Suggested remediation */
  remediation?: string;
  /** OWASP reference */
  owaspRef?: string;
}

// ─── Assertions ─────────────────────────────────────────────────────────────

export type AssertionType =
  | "tool_called"
  | "tool_not_called"
  | "output_contains"
  | "output_not_contains"
  | "output_matches"
  | "steps_under"
  | "cost_under"
  | "no_sensitive_data"
  | "no_tool_errors"
  | "custom";

export interface Assertion {
  type: AssertionType;
  value: string | number | RegExp;
  message?: string;
}

export interface AssertionResult {
  assertion: Assertion;
  passed: boolean;
  actual: string | number;
  message: string;
}

// ─── Config ─────────────────────────────────────────────────────────────────

export interface KraitConfig {
  version: string;
  agents: AgentDefinition[];
  suites?: string[];
  probes?: ProbeCategory[];
  assertions?: Assertion[];
  settings?: KraitSettings;
}

export interface KraitSettings {
  concurrency?: number;
  timeout?: number;
  verbose?: boolean;
  outputFormat?: "cli" | "json" | "html";
  outputFile?: string;
}

// ─── Scan Results ───────────────────────────────────────────────────────────

export interface ScanResult {
  agent: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  summary: ScanSummary;
  results: ProbeResult[];
}

export interface ScanSummary {
  total: number;
  passed: number;
  failed: number;
  errors: number;
  skipped: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanReport {
  version: string;
  timestamp: string;
  agents: ScanResult[];
  overallSummary: ScanSummary;
}
