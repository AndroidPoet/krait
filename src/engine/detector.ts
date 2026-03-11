import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { globSync } from "glob";
import type { AgentDefinition, ToolDefinition } from "../types/index.js";

/**
 * Agent Framework Auto-Detector
 *
 * Scans your project directory to detect AI agent frameworks and
 * extract tool definitions automatically. Zero config needed.
 *
 * Supported frameworks:
 *   - LangChain / LangGraph (Python & JS)
 *   - CrewAI
 *   - OpenAI Assistants / Swarm
 *   - Vercel AI SDK
 *   - AutoGen / AG2
 *   - Semantic Kernel
 *   - Mastra
 *   - Custom agents (heuristic detection)
 */

export interface DetectedAgent {
  name: string;
  framework: string;
  description: string;
  tools: ToolDefinition[];
  files: string[];
  confidence: number;
}

export interface DetectionResult {
  agents: DetectedAgent[];
  framework: string | null;
  configSuggestion: string;
}

interface FrameworkPattern {
  name: string;
  /** Files/imports that indicate this framework */
  indicators: RegExp[];
  /** Patterns to extract tool names */
  toolPatterns: RegExp[];
  /** File globs to search */
  fileGlobs: string[];
}

const FRAMEWORKS: FrameworkPattern[] = [
  {
    name: "langchain",
    indicators: [
      /from\s+langchain/,
      /import\s+.*langchain/,
      /require\(["']langchain/,
      /@langchain\//,
    ],
    toolPatterns: [
      /Tool\(\s*name\s*=\s*["'](\w+)["']/g,
      /StructuredTool\(\s*name\s*=\s*["'](\w+)["']/g,
      /@tool\s*\n\s*(?:async\s+)?def\s+(\w+)/g,
      /new\s+DynamicTool\(\{\s*name:\s*["'](\w+)["']/g,
      /\.tool\(\s*["'](\w+)["']/g,
    ],
    fileGlobs: ["**/*.py", "**/*.ts", "**/*.js"],
  },
  {
    name: "crewai",
    indicators: [/from\s+crewai/, /import\s+crewai/, /CrewAI/],
    toolPatterns: [
      /@tool\s*\n\s*def\s+(\w+)/g,
      /Tool\(\s*name\s*=\s*["'](\w+)["']/g,
      /tools\s*=\s*\[([^\]]+)\]/g,
    ],
    fileGlobs: ["**/*.py"],
  },
  {
    name: "openai-assistants",
    indicators: [
      /client\.beta\.assistants/,
      /openai\.beta\.assistants/,
      /type:\s*["']function["']/,
      /function_declarations/,
    ],
    toolPatterns: [
      /["']name["']\s*:\s*["'](\w+)["']/g,
      /function\s*:\s*\{\s*name:\s*["'](\w+)["']/g,
    ],
    fileGlobs: ["**/*.py", "**/*.ts", "**/*.js"],
  },
  {
    name: "vercel-ai-sdk",
    indicators: [
      /from\s+["']ai["']/,
      /import\s+.*["']ai["']/,
      /import\s+.*["']@ai-sdk/,
      /createStreamableUI/,
      /generateText/,
      /streamText/,
    ],
    toolPatterns: [
      /tool\(\s*["'](\w+)["']/g,
      /tools:\s*\{([^}]+)\}/g,
      /(\w+):\s*tool\(/g,
    ],
    fileGlobs: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"],
  },
  {
    name: "autogen",
    indicators: [
      /from\s+autogen/,
      /import\s+autogen/,
      /ConversableAgent/,
      /AssistantAgent/,
    ],
    toolPatterns: [
      /register_function\(\s*(\w+)/g,
      /def\s+(\w+).*# tool/gi,
      /function_map\s*=\s*\{([^}]+)\}/g,
    ],
    fileGlobs: ["**/*.py"],
  },
  {
    name: "semantic-kernel",
    indicators: [
      /import\s+semantic_kernel/,
      /from\s+semantic_kernel/,
      /Microsoft\.SemanticKernel/,
      /KernelFunction/,
    ],
    toolPatterns: [
      /@kernel_function\s*.*\n\s*(?:async\s+)?def\s+(\w+)/g,
      /\[KernelFunction\].*\n.*\s+(\w+)\(/g,
    ],
    fileGlobs: ["**/*.py", "**/*.cs"],
  },
  {
    name: "mastra",
    indicators: [/from\s+["']mastra["']/, /import\s+.*["']mastra["']/, /createTool/],
    toolPatterns: [
      /createTool\(\s*\{\s*id:\s*["'](\w+)["']/g,
      /tools:\s*\{([^}]+)\}/g,
    ],
    fileGlobs: ["**/*.ts", "**/*.js"],
  },
];

/** Dangerous tool name patterns */
const DESTRUCTIVE_NAMES = /delete|remove|drop|purge|send|write|modify|update|create|execute|run|kill|stop|restart/i;
const SENSITIVE_NAMES = /user|customer|email|profile|account|data|credential|secret|password|token|key|pii|record/i;
const SHELL_NAMES = /exec|shell|bash|command|spawn|eval|terminal|process/i;

/**
 * Scan a project directory and detect AI agent frameworks + tools.
 */
export function detectAgents(projectDir: string): DetectionResult {
  const agents: DetectedAgent[] = [];
  let detectedFramework: string | null = null;

  // Ignore patterns
  const ignorePatterns = [
    "**/node_modules/**",
    "**/venv/**",
    "**/.venv/**",
    "**/dist/**",
    "**/build/**",
    "**/__pycache__/**",
    "**/.git/**",
  ];

  for (const fw of FRAMEWORKS) {
    const files = globSync(fw.fileGlobs, {
      cwd: projectDir,
      ignore: ignorePatterns,
      absolute: true,
    }).slice(0, 200); // Cap file scanning

    const matchingFiles: string[] = [];
    const allToolNames = new Set<string>();

    for (const file of files) {
      let content: string;
      try {
        content = readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      // Check if this file uses the framework
      const matches = fw.indicators.some((pattern) => pattern.test(content));
      if (!matches) continue;

      matchingFiles.push(file);
      detectedFramework = fw.name;

      // Extract tool names
      for (const pattern of fw.toolPatterns) {
        // Reset lastIndex for global regexes
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const toolName = match[1];
          if (toolName && toolName.length > 1 && toolName.length < 50) {
            allToolNames.add(toolName);
          }
        }
      }
    }

    if (matchingFiles.length > 0) {
      const tools: ToolDefinition[] = Array.from(allToolNames).map(
        (name) => ({
          name,
          description: `Auto-detected from ${fw.name}`,
          destructive: DESTRUCTIVE_NAMES.test(name),
          sensitive: SENSITIVE_NAMES.test(name),
          permissions: SHELL_NAMES.test(name) ? ["admin"] : undefined,
        })
      );

      agents.push({
        name: `${fw.name}-agent`,
        framework: fw.name,
        description: `Auto-detected ${fw.name} agent`,
        tools,
        files: matchingFiles.map((f) => f.replace(projectDir + "/", "")),
        confidence: matchingFiles.length > 3 ? 0.9 : matchingFiles.length > 1 ? 0.7 : 0.5,
      });
    }
  }

  // Generate YAML config suggestion
  const configSuggestion = generateConfig(agents);

  return { agents, framework: detectedFramework, configSuggestion };
}

function generateConfig(agents: DetectedAgent[]): string {
  if (agents.length === 0) {
    return `# krait could not auto-detect an agent framework.
# Configure your agent manually:
version: "1"

agents:
  - name: "my-agent"
    description: "My AI agent"
    provider:
      type: http
      endpoint: http://localhost:3000/agent
    tools:
      - name: my_tool
        description: "What this tool does"
    maxSteps: 15
    maxCost: 0.50
`;
  }

  const agentConfigs = agents.map((agent) => {
    const toolConfigs = agent.tools
      .map((t) => {
        const flags = [
          t.sensitive ? "        sensitive: true" : null,
          t.destructive ? "        destructive: true" : null,
          t.permissions?.length
            ? `        permissions:\n          - ${t.permissions.join("\n          - ")}`
            : null,
        ]
          .filter(Boolean)
          .join("\n");

        return `      - name: ${t.name}\n        description: "${t.description}"${flags ? "\n" + flags : ""}`;
      })
      .join("\n");

    return `  - name: "${agent.name}"
    description: "${agent.description} (${agent.files.length} files)"
    provider:
      type: http
      endpoint: http://localhost:3000/agent  # Update this
    tools:
${toolConfigs}
    maxSteps: 15
    maxCost: 0.50`;
  });

  return `# Auto-generated by krait auto-detect
# Framework detected: ${agents[0]?.framework}
# Review and update the provider endpoint before scanning.

version: "1"

settings:
  timeout: 15000
  verbose: true

agents:
${agentConfigs.join("\n\n")}
`;
}
