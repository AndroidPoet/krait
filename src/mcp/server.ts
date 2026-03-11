#!/usr/bin/env node

/**
 * krait MCP Server — Security Advisor for AI Coding Tools
 *
 * Exposes krait's security scanning capabilities as MCP tools that any
 * AI coding assistant (Claude Code, Cursor, Windsurf, etc.) can call.
 *
 * Tools:
 *   krait_scan        — Run security probes against an agent config
 *   krait_audit       — Static analysis of agent configuration
 *   krait_check_tool  — Check if a single tool definition is secure
 *   krait_suggest      — Get security recommendations for an agent
 *
 * Protocol: JSON-RPC over stdin/stdout (MCP standard)
 *
 * Usage:
 *   Add to claude_desktop_config.json or .claude/settings.json:
 *   {
 *     "mcpServers": {
 *       "krait": {
 *         "command": "npx",
 *         "args": ["krait", "mcp"]
 *       }
 *     }
 *   }
 */

import { loadConfig } from "../config/loader.js";
import { ScanRunner } from "../engine/runner.js";
import { auditAgents, type AuditFinding } from "../engine/auditor.js";
import { getAllProbes } from "../probes/index.js";
import type { AgentDefinition, ToolDefinition } from "../types/index.js";

// ─── MCP Protocol Types ──────────────────────────────────────────────────────

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

// ─── Tool Definitions ────────────────────────────────────────────────────────

const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "krait_scan",
    description:
      "Run krait security probes against an agent configuration file. " +
      "Returns pass/fail results with severity, evidence, and remediation for each probe. " +
      "Use this when you want to security-test an AI agent.",
    inputSchema: {
      type: "object",
      properties: {
        config_path: {
          type: "string",
          description: "Path to the krait YAML config file (e.g., krait.yaml)",
        },
        probes: {
          type: "string",
          description:
            "Comma-separated probe categories to run (e.g., 'goal-hijacking,tool-misuse'). Omit for all probes.",
        },
      },
      required: ["config_path"],
    },
  },
  {
    name: "krait_audit",
    description:
      "Static analysis of an agent configuration file. Finds dangerous patterns " +
      "like destructive tools without permissions, missing rate limits, and " +
      "shell execution tools. Zero cost — no agent invocation needed.",
    inputSchema: {
      type: "object",
      properties: {
        config_path: {
          type: "string",
          description: "Path to the krait YAML config file",
        },
      },
      required: ["config_path"],
    },
  },
  {
    name: "krait_check_tool",
    description:
      "Check if a single tool definition is secure. Pass the tool's name, description, " +
      "and flags. Returns security warnings and recommendations. " +
      "Use this when reviewing individual tool definitions in agent code.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Tool name (e.g., 'delete_user', 'send_email')",
        },
        description: {
          type: "string",
          description: "Tool description",
        },
        destructive: {
          type: "boolean",
          description: "Whether the tool causes side effects",
        },
        sensitive: {
          type: "boolean",
          description: "Whether the tool accesses sensitive/PII data",
        },
        permissions: {
          type: "array",
          items: { type: "string" },
          description: "Required permissions to use this tool",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "krait_suggest",
    description:
      "Get security recommendations for an agent based on its tools and configuration. " +
      "Returns prioritized suggestions for improving agent security. " +
      "Use this when designing or reviewing an AI agent's architecture.",
    inputSchema: {
      type: "object",
      properties: {
        agent_name: {
          type: "string",
          description: "Name of the agent",
        },
        agent_description: {
          type: "string",
          description: "What the agent does",
        },
        tools: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              description: { type: "string" },
              destructive: { type: "boolean" },
              sensitive: { type: "boolean" },
              permissions: { type: "array", items: { type: "string" } },
            },
            required: ["name"],
          },
          description: "List of tools the agent has access to",
        },
        max_steps: { type: "number", description: "Max steps per run" },
        max_cost: { type: "number", description: "Max cost per run (USD)" },
      },
      required: ["agent_name", "tools"],
    },
  },
];

// ─── Tool Handlers ───────────────────────────────────────────────────────────

async function handleScan(params: Record<string, unknown>): Promise<string> {
  const configPath = params.config_path as string;
  if (!configPath) return "Error: config_path is required";

  try {
    const config = await loadConfig(configPath);
    const runner = new ScanRunner({
      timeout: config.settings?.timeout || 10000,
    });
    const probes = getAllProbes();

    const results = [];
    for (const agent of config.agents) {
      const result = await runner.scan(agent, probes);

      const failures = result.results
        .filter((r) => r.status === "fail")
        .map((r) => ({
          probe: r.probeName,
          severity: r.severity,
          finding: r.finding,
          evidence: r.evidence,
          remediation: r.remediation,
          owasp: r.owaspRef,
        }));

      results.push({
        agent: agent.name,
        summary: result.summary,
        duration: `${result.durationMs}ms`,
        failures,
      });
    }

    return JSON.stringify(results, null, 2);
  } catch (err) {
    return `Error: ${err instanceof Error ? err.message : String(err)}`;
  }
}

async function handleAudit(params: Record<string, unknown>): Promise<string> {
  const configPath = params.config_path as string;
  if (!configPath) return "Error: config_path is required";

  try {
    const config = await loadConfig(configPath);
    const findings = auditAgents(config.agents);

    if (findings.length === 0) {
      return "No configuration issues found. The agent config follows security best practices.";
    }

    return JSON.stringify(
      findings.map((f) => ({
        severity: f.severity,
        rule: f.rule,
        agent: f.agent,
        issue: f.message,
        fix: f.remediation,
      })),
      null,
      2
    );
  } catch (err) {
    return `Error: ${err instanceof Error ? err.message : String(err)}`;
  }
}

function handleCheckTool(params: Record<string, unknown>): string {
  const name = (params.name as string) || "";
  const description = (params.description as string) || "";
  const destructive = params.destructive as boolean;
  const sensitive = params.sensitive as boolean;
  const permissions = (params.permissions as string[]) || [];

  const warnings: string[] = [];
  const suggestions: string[] = [];
  const nameLower = name.toLowerCase();
  const descLower = description.toLowerCase();

  // Dangerous tool name patterns
  const dangerousNames = [
    "exec",
    "shell",
    "bash",
    "command",
    "spawn",
    "eval",
    "run",
  ];
  const sensitiveNames = [
    "user",
    "customer",
    "email",
    "profile",
    "account",
    "data",
    "credential",
    "secret",
    "password",
    "token",
    "key",
  ];
  const destructiveNames = [
    "delete",
    "remove",
    "drop",
    "purge",
    "send",
    "write",
    "modify",
    "update",
    "create",
  ];
  const externalNames = [
    "email",
    "send",
    "webhook",
    "notify",
    "slack",
    "http",
    "fetch",
    "post",
  ];

  // Check for dangerous tool types
  if (dangerousNames.some((d) => nameLower.includes(d) || descLower.includes(d))) {
    warnings.push(
      `CRITICAL: "${name}" appears to be a shell/command execution tool. This is the highest-risk tool category.`
    );
    suggestions.push(
      "Require: strict input sanitization, command allowlisting, approval workflow, sandbox isolation"
    );
    if (!destructive) {
      warnings.push(
        'Should be marked destructive: true — shell execution can cause irreversible side effects'
      );
    }
    if (!permissions.length) {
      warnings.push(
        "Should require permissions (e.g., ['admin']) — unrestricted shell access is dangerous"
      );
    }
  }

  // Check for sensitive data access
  if (sensitiveNames.some((s) => nameLower.includes(s) || descLower.includes(s))) {
    if (!sensitive) {
      warnings.push(
        `"${name}" likely accesses sensitive data but is not marked sensitive: true`
      );
      suggestions.push(
        "Add sensitive: true to enable data-exfiltration probes and PII redaction checks"
      );
    }
  }

  // Check destructive tools without permissions
  if (
    destructive &&
    !permissions.length &&
    destructiveNames.some((d) => nameLower.includes(d) || descLower.includes(d))
  ) {
    warnings.push(
      `CRITICAL: "${name}" is destructive but has no permission gates. Any user can invoke it.`
    );
    suggestions.push(
      "Add permissions: ['admin'] or appropriate role to enforce RBAC"
    );
  }

  // Check for implied destructive
  if (
    !destructive &&
    destructiveNames.some((d) => nameLower.includes(d) || descLower.includes(d))
  ) {
    warnings.push(
      `"${name}" appears to modify state but is not marked destructive: true`
    );
    suggestions.push(
      "Add destructive: true to enable tool-misuse probes and confirmation gates"
    );
  }

  // Check for external communication
  if (externalNames.some((e) => nameLower.includes(e) || descLower.includes(e))) {
    warnings.push(
      `"${name}" can communicate externally — this is a data exfiltration vector`
    );
    suggestions.push(
      "Add: recipient allowlisting, content filtering for PII/secrets, rate limiting"
    );
  }

  if (warnings.length === 0) {
    return `✓ "${name}" looks well-configured. No security issues detected.`;
  }

  return [
    `Security review for tool "${name}":`,
    "",
    "Warnings:",
    ...warnings.map((w) => `  ⚠ ${w}`),
    "",
    "Suggestions:",
    ...suggestions.map((s) => `  → ${s}`),
  ].join("\n");
}

function handleSuggest(params: Record<string, unknown>): string {
  const agentName = (params.agent_name as string) || "agent";
  const tools = (params.tools as ToolDefinition[]) || [];
  const maxSteps = params.max_steps as number | undefined;
  const maxCost = params.max_cost as number | undefined;

  const agent: AgentDefinition = {
    name: agentName,
    description: params.agent_description as string,
    provider: { type: "mock", responses: [] },
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description || "",
      destructive: t.destructive,
      sensitive: t.sensitive,
      permissions: t.permissions,
    })),
    maxSteps,
    maxCost,
  };

  const findings = auditAgents([agent]);
  const suggestions: string[] = [];

  // Add audit findings
  for (const f of findings) {
    suggestions.push(
      `[${f.severity.toUpperCase()}] ${f.message}\n  Fix: ${f.remediation}`
    );
  }

  // General recommendations based on tool count
  if (tools.length > 15) {
    suggestions.push(
      `[MEDIUM] Agent has ${tools.length} tools — consider splitting into specialized agents with fewer tools each to reduce attack surface.`
    );
  }

  if (tools.length > 0 && !tools.some((t) => t.destructive || t.sensitive)) {
    suggestions.push(
      "[HIGH] No tools are annotated as destructive or sensitive. Without annotations, krait can't generate targeted probes. Review each tool and add appropriate flags."
    );
  }

  // Confirmation gates
  const destructiveWithoutConfirm = tools.filter(
    (t) => t.destructive && !t.permissions?.length
  );
  if (destructiveWithoutConfirm.length > 0) {
    suggestions.push(
      `[CRITICAL] These destructive tools lack permission gates: ${destructiveWithoutConfirm.map((t) => t.name).join(", ")}. Add a confirmation workflow or RBAC check before execution.`
    );
  }

  if (suggestions.length === 0) {
    return `✓ "${agentName}" follows security best practices. No recommendations.`;
  }

  return [
    `Security recommendations for "${agentName}":`,
    "",
    ...suggestions.map((s, i) => `${i + 1}. ${s}`),
    "",
    `Run 'krait scan' to test with ${getAllProbes().length} probes across 7 OWASP categories.`,
  ].join("\n");
}

// ─── MCP Protocol Handler ────────────────────────────────────────────────────

function handleRequest(req: JsonRpcRequest): JsonRpcResponse {
  const { id, method, params } = req;

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: {
            name: "krait",
            version: "0.2.0",
          },
        },
      };

    case "notifications/initialized":
      // No response needed for notifications
      return { jsonrpc: "2.0", id, result: {} };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: MCP_TOOLS,
        },
      };

    case "tools/call": {
      const toolName = (params as { name: string })?.name;
      const toolArgs = (params as { arguments?: Record<string, unknown> })
        ?.arguments || {};

      // Return a pending response — actual work happens async
      return {
        jsonrpc: "2.0",
        id,
        result: { _pending: true, tool: toolName, args: toolArgs },
      };
    }

    case "ping":
      return { jsonrpc: "2.0", id, result: {} };

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  switch (name) {
    case "krait_scan":
      return handleScan(args);
    case "krait_audit":
      return handleAudit(args);
    case "krait_check_tool":
      return handleCheckTool(args);
    case "krait_suggest":
      return handleSuggest(args);
    default:
      return `Unknown tool: ${name}`;
  }
}

// ─── Server Loop ─────────────────────────────────────────────────────────────

export async function startMcpServer(): Promise<void> {
  const stdin = process.stdin;
  const stdout = process.stdout;

  stdin.setEncoding("utf8");

  let buffer = "";

  stdin.on("data", async (chunk: string) => {
    buffer += chunk;

    // Process complete JSON-RPC messages
    while (true) {
      // Look for Content-Length header
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) break;

      const header = buffer.slice(0, headerEnd);
      const lengthMatch = header.match(/Content-Length:\s*(\d+)/i);
      if (!lengthMatch) {
        // Try parsing as raw JSON (some clients skip headers)
        const newlineIdx = buffer.indexOf("\n");
        if (newlineIdx === -1) break;

        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);

        if (line) {
          try {
            const req = JSON.parse(line) as JsonRpcRequest;
            await processRequest(req, stdout);
          } catch {
            // Skip malformed lines
          }
        }
        continue;
      }

      const contentLength = parseInt(lengthMatch[1]);
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + contentLength;

      if (buffer.length < bodyEnd) break;

      const body = buffer.slice(bodyStart, bodyEnd);
      buffer = buffer.slice(bodyEnd);

      try {
        const req = JSON.parse(body) as JsonRpcRequest;
        await processRequest(req, stdout);
      } catch {
        // Skip malformed messages
      }
    }
  });

  stdin.on("end", () => {
    process.exit(0);
  });
}

async function processRequest(
  req: JsonRpcRequest,
  stdout: NodeJS.WriteStream
): Promise<void> {
  const response = handleRequest(req);

  // Handle async tool calls
  if (
    response.result &&
    typeof response.result === "object" &&
    (response.result as Record<string, unknown>)._pending
  ) {
    const pending = response.result as {
      tool: string;
      args: Record<string, unknown>;
    };

    try {
      const text = await handleToolCall(pending.tool, pending.args);
      sendResponse(stdout, {
        jsonrpc: "2.0",
        id: req.id,
        result: {
          content: [{ type: "text", text }],
        },
      });
    } catch (err) {
      sendResponse(stdout, {
        jsonrpc: "2.0",
        id: req.id,
        result: {
          content: [
            {
              type: "text",
              text: `Error: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        },
      });
    }
    return;
  }

  // Skip sending response for notifications (no id)
  if (req.method.startsWith("notifications/")) return;

  sendResponse(stdout, response);
}

function sendResponse(
  stdout: NodeJS.WriteStream,
  response: JsonRpcResponse
): void {
  const body = JSON.stringify(response);
  const message = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
  stdout.write(message);
}
