import { readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import type { AgentDefinition, ToolDefinition, KraitConfig, KraitSettings } from "../types/index.js";

interface RawConfig {
  version?: string;
  settings?: KraitSettings;
  agents: RawAgent[];
  suites?: string[];
  probes?: string[];
}

interface RawAgent {
  name: string;
  description?: string;
  provider: {
    type: string;
    endpoint?: string;
    headers?: Record<string, string>;
    command?: string;
    args?: string[];
    responses?: { input?: string; output: string }[];
  };
  tools: RawTool[];
  systemPrompt?: string;
  maxSteps?: number;
  maxCost?: number;
}

interface RawTool {
  name: string;
  description: string;
  destructive?: boolean;
  sensitive?: boolean;
  permissions?: string[];
}

/** Load and parse a krait YAML config file */
export async function loadConfig(configPath: string): Promise<KraitConfig> {
  const content = await readFile(configPath, "utf-8");
  const raw = parseYaml(content) as RawConfig;

  if (!raw.agents || !Array.isArray(raw.agents)) {
    throw new Error(`Invalid config: "agents" array is required`);
  }

  const agents: AgentDefinition[] = raw.agents.map(parseAgent);

  return {
    version: raw.version || "1",
    agents,
    suites: raw.suites,
    probes: raw.probes as KraitConfig["probes"],
    settings: raw.settings,
  };
}

function parseAgent(raw: RawAgent): AgentDefinition {
  if (!raw.name) throw new Error("Agent must have a name");
  if (!raw.provider) throw new Error(`Agent "${raw.name}" must have a provider`);

  const tools: ToolDefinition[] = (raw.tools || []).map((t) => ({
    name: t.name,
    description: t.description,
    destructive: t.destructive,
    sensitive: t.sensitive,
    permissions: t.permissions,
  }));

  let provider: AgentDefinition["provider"];

  switch (raw.provider.type) {
    case "http":
      if (!raw.provider.endpoint)
        throw new Error(`Agent "${raw.name}": HTTP provider requires endpoint`);
      provider = {
        type: "http",
        endpoint: raw.provider.endpoint,
        headers: raw.provider.headers,
      };
      break;

    case "command":
      if (!raw.provider.command)
        throw new Error(`Agent "${raw.name}": Command provider requires command`);
      provider = {
        type: "command",
        command: raw.provider.command,
        args: raw.provider.args,
      };
      break;

    case "mock":
      provider = {
        type: "mock",
        responses: (raw.provider.responses || []).map((r) => ({
          input: r.input,
          output: r.output,
          steps: [],
        })),
      };
      break;

    default:
      throw new Error(
        `Agent "${raw.name}": Unknown provider type "${raw.provider.type}". Use "http", "command", or "mock".`
      );
  }

  return {
    name: raw.name,
    description: raw.description,
    provider,
    tools,
    systemPrompt: raw.systemPrompt,
    maxSteps: raw.maxSteps,
    maxCost: raw.maxCost,
  };
}
