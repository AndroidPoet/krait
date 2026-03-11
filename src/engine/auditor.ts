import type { AgentDefinition, Severity } from "../types/index.js";

/**
 * Config Auditor
 *
 * Static analysis of agent YAML definitions to detect dangerous
 * configurations BEFORE running any probes. Zero cost, instant results.
 *
 * Inspired by OpenClaw's collectGatewayConfigFindings engine.
 */

export interface AuditFinding {
  rule: string;
  severity: Severity;
  message: string;
  remediation: string;
  agent: string;
}

interface AuditRule {
  id: string;
  severity: Severity;
  check: (agent: AgentDefinition) => AuditFinding | null;
}

const RULES: AuditRule[] = [
  // ── Tool Configuration ──

  {
    id: "no-tool-annotations",
    severity: "high",
    check: (agent) => {
      const unannotated = agent.tools.filter((t) => !t.destructive && !t.sensitive);
      if (unannotated.length === agent.tools.length && agent.tools.length > 0) {
        return {
          rule: "no-tool-annotations",
          severity: "high",
          message: `All ${agent.tools.length} tools lack 'destructive' or 'sensitive' annotations. krait cannot distinguish safe from dangerous tools.`,
          remediation:
            "Mark tools with destructive: true (for state-changing ops) and sensitive: true (for PII-accessing ops). This enables targeted probe generation.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "destructive-without-permissions",
    severity: "critical",
    check: (agent) => {
      const unguarded = agent.tools.filter(
        (t) => t.destructive && (!t.permissions || t.permissions.length === 0)
      );
      if (unguarded.length > 0) {
        return {
          rule: "destructive-without-permissions",
          severity: "critical",
          message: `Destructive tools without permission gates: ${unguarded.map((t) => t.name).join(", ")}. Any user can invoke these.`,
          remediation:
            "Add permissions: ['admin'] (or appropriate role) to destructive tools. This enforces RBAC before execution.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "sensitive-without-annotation",
    severity: "high",
    check: (agent) => {
      const suspectNames = [
        "user",
        "customer",
        "email",
        "profile",
        "account",
        "data",
        "record",
        "credential",
        "secret",
        "password",
        "token",
        "key",
      ];
      const unmarked = agent.tools.filter(
        (t) =>
          !t.sensitive &&
          suspectNames.some(
            (s) =>
              t.name.toLowerCase().includes(s) ||
              (t.description && t.description.toLowerCase().includes(s))
          )
      );
      if (unmarked.length > 0) {
        return {
          rule: "sensitive-without-annotation",
          severity: "high",
          message: `Tools likely handling sensitive data but not marked sensitive: ${unmarked.map((t) => t.name).join(", ")}`,
          remediation:
            "Add sensitive: true to tools that access PII, credentials, or confidential data. This enables data-exfiltration probes.",
          agent: agent.name,
        };
      }
      return null;
    },
  },

  // ── Resource Limits ──

  {
    id: "no-max-steps",
    severity: "high",
    check: (agent) => {
      if (!agent.maxSteps) {
        return {
          rule: "no-max-steps",
          severity: "high",
          message: "No maxSteps limit configured. Agent can execute unlimited tool calls.",
          remediation:
            "Set maxSteps (e.g., 10-25) to prevent infinite loops and unbounded tool-call chains.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "max-steps-too-high",
    severity: "medium",
    check: (agent) => {
      if (agent.maxSteps && agent.maxSteps > 50) {
        return {
          rule: "max-steps-too-high",
          severity: "medium",
          message: `maxSteps is ${agent.maxSteps} — unusually high. Most agent tasks complete in under 20 steps.`,
          remediation:
            "Consider lowering maxSteps. High limits increase blast radius if the agent enters a loop or is hijacked.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "no-max-cost",
    severity: "high",
    check: (agent) => {
      if (!agent.maxCost) {
        return {
          rule: "no-max-cost",
          severity: "high",
          message: "No maxCost limit configured. Agent can spend unlimited budget per run.",
          remediation:
            "Set maxCost (e.g., 0.50) to prevent cost explosion attacks and runaway API bills.",
          agent: agent.name,
        };
      }
      return null;
    },
  },

  // ── Tool Count & Surface Area ──

  {
    id: "excessive-tools",
    severity: "medium",
    check: (agent) => {
      if (agent.tools.length > 20) {
        return {
          rule: "excessive-tools",
          severity: "medium",
          message: `Agent has ${agent.tools.length} tools — large attack surface. More tools = more ways to misuse the agent.`,
          remediation:
            "Apply principle of least privilege: only provide the tools the agent actually needs. Consider splitting into specialized agents with fewer tools each.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "no-tools-defined",
    severity: "medium",
    check: (agent) => {
      if (agent.tools.length === 0) {
        return {
          rule: "no-tools-defined",
          severity: "medium",
          message: "No tools defined. krait can't generate tool-specific attacks without tool definitions.",
          remediation:
            "Define the agent's tools with name, description, and security annotations (destructive, sensitive, permissions).",
          agent: agent.name,
        };
      }
      return null;
    },
  },

  // ── Dangerous Tool Patterns ──

  {
    id: "shell-execution-tool",
    severity: "critical",
    check: (agent) => {
      const shellTools = agent.tools.filter((t) => {
        const name = t.name.toLowerCase();
        const desc = (t.description || "").toLowerCase();
        return (
          name.includes("exec") ||
          name.includes("shell") ||
          name.includes("bash") ||
          name.includes("command") ||
          name.includes("spawn") ||
          desc.includes("execute") ||
          desc.includes("shell") ||
          desc.includes("command line")
        );
      });
      if (shellTools.length > 0) {
        return {
          rule: "shell-execution-tool",
          severity: "critical",
          message: `Agent has shell/command execution tools: ${shellTools.map((t) => t.name).join(", ")}. This is the highest-risk tool category.`,
          remediation:
            "Shell execution tools require: (1) strict input sanitization, (2) command allowlisting, (3) approval workflow, (4) sandbox isolation. Mark as destructive with admin permissions.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "file-write-tool",
    severity: "high",
    check: (agent) => {
      const fileTools = agent.tools.filter((t) => {
        const name = t.name.toLowerCase();
        const desc = (t.description || "").toLowerCase();
        return (
          (name.includes("file") || name.includes("fs")) &&
          (name.includes("write") ||
            name.includes("delete") ||
            name.includes("move") ||
            desc.includes("write") ||
            desc.includes("delete") ||
            desc.includes("modify"))
        );
      });
      if (fileTools.length > 0 && !fileTools.every((t) => t.destructive)) {
        return {
          rule: "file-write-tool",
          severity: "high",
          message: `File-modifying tools not all marked destructive: ${fileTools.filter((t) => !t.destructive).map((t) => t.name).join(", ")}`,
          remediation:
            "File write/delete/move tools should be marked destructive: true with path-boundary validation to prevent traversal attacks.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "external-communication-tool",
    severity: "high",
    check: (agent) => {
      const commTools = agent.tools.filter((t) => {
        const name = t.name.toLowerCase();
        const desc = (t.description || "").toLowerCase();
        return (
          name.includes("email") ||
          name.includes("send") ||
          name.includes("webhook") ||
          name.includes("notify") ||
          name.includes("slack") ||
          name.includes("http") ||
          name.includes("fetch") ||
          desc.includes("send") ||
          desc.includes("external") ||
          desc.includes("webhook")
        );
      });
      if (commTools.length > 0) {
        return {
          rule: "external-communication-tool",
          severity: "high",
          message: `Agent can communicate externally via: ${commTools.map((t) => t.name).join(", ")}. This is a data exfiltration vector.`,
          remediation:
            "External communication tools need: (1) recipient allowlisting, (2) content filtering for PII/secrets, (3) rate limiting. Mark as destructive.",
          agent: agent.name,
        };
      }
      return null;
    },
  },

  // ── Provider Security ──

  {
    id: "command-provider-no-sandbox",
    severity: "medium",
    check: (agent) => {
      if (agent.provider.type === "command") {
        return {
          rule: "command-provider-no-sandbox",
          severity: "medium",
          message: "Agent uses command provider — executes as a local process with host access.",
          remediation:
            "Consider running command-based agents in a sandbox (Docker, nsjail) to limit blast radius if the agent is compromised.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
  {
    id: "http-provider-no-auth",
    severity: "high",
    check: (agent) => {
      if (
        agent.provider.type === "http" &&
        !agent.provider.headers?.["Authorization"] &&
        !agent.provider.headers?.["authorization"] &&
        !agent.provider.headers?.["x-api-key"]
      ) {
        return {
          rule: "http-provider-no-auth",
          severity: "high",
          message: "HTTP provider has no Authorization or API key header. The agent endpoint may be unauthenticated.",
          remediation:
            "Add authentication headers to the HTTP provider configuration. Unauthenticated agent endpoints are vulnerable to abuse.",
          agent: agent.name,
        };
      }
      return null;
    },
  },
];

/**
 * Run all audit rules against an agent definition.
 */
export function auditAgent(agent: AgentDefinition): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const rule of RULES) {
    const finding = rule.check(agent);
    if (finding) {
      findings.push(finding);
    }
  }

  return findings;
}

/**
 * Run audit rules against multiple agents.
 */
export function auditAgents(agents: AgentDefinition[]): AuditFinding[] {
  return agents.flatMap(auditAgent);
}

export { RULES as AUDIT_RULES };
