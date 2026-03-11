/**
 * LLM Provider Abstraction
 *
 * Supports Anthropic, OpenAI, and any OpenAI-compatible API
 * (Ollama, Together, Groq, OpenRouter, etc.)
 *
 * Uses raw fetch — zero SDK dependencies.
 */

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMOptions {
  temperature?: number;
  maxTokens?: number;
}

export interface LLMProvider {
  name: string;
  generate(messages: LLMMessage[], options?: LLMOptions): Promise<string>;
}

export interface ProviderConfig {
  type: "anthropic" | "openai" | "ollama";
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

/**
 * Anthropic Claude — Messages API
 */
function createAnthropicProvider(config: ProviderConfig): LLMProvider {
  const apiKey = config.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      "Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass apiKey in config."
    );
  }

  const baseUrl = config.baseUrl || "https://api.anthropic.com";

  return {
    name: `anthropic/${config.model}`,
    async generate(messages, options = {}) {
      const systemMsg = messages.find((m) => m.role === "system");
      const userMsgs = messages.filter((m) => m.role !== "system");

      const body: Record<string, unknown> = {
        model: config.model,
        max_tokens: options.maxTokens || 4096,
        temperature: options.temperature ?? 0.8,
        messages: userMsgs.map((m) => ({ role: m.role, content: m.content })),
      };

      if (systemMsg) {
        body.system = systemMsg.content;
      }

      const res = await fetch(`${baseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.text();
        throw new Error(`Anthropic API error (${res.status}): ${err}`);
      }

      const data = (await res.json()) as {
        content: Array<{ type: string; text: string }>;
      };
      return data.content
        .filter((b) => b.type === "text")
        .map((b) => b.text)
        .join("");
    },
  };
}

/**
 * OpenAI-compatible — Chat Completions API
 * Works with: OpenAI, Ollama, Together, Groq, OpenRouter, LiteLLM, etc.
 */
function createOpenAIProvider(config: ProviderConfig): LLMProvider {
  const isOllama = config.type === "ollama";
  const apiKey = config.apiKey || process.env.OPENAI_API_KEY || (isOllama ? "ollama" : undefined);

  if (!apiKey && !isOllama) {
    throw new Error(
      "OpenAI API key required. Set OPENAI_API_KEY env var or pass apiKey in config."
    );
  }

  const baseUrl =
    config.baseUrl ||
    (isOllama ? "http://localhost:11434" : "https://api.openai.com");

  const chatPath = isOllama ? "/api/chat" : "/v1/chat/completions";

  return {
    name: `${config.type}/${config.model}`,
    async generate(messages, options = {}) {
      const body: Record<string, unknown> = {
        model: config.model,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        temperature: options.temperature ?? 0.8,
        max_tokens: options.maxTokens || 4096,
      };

      // Ollama uses 'stream: false' for non-streaming
      if (isOllama) {
        body.stream = false;
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (apiKey && !isOllama) {
        headers["Authorization"] = `Bearer ${apiKey}`;
      }

      const res = await fetch(`${baseUrl}${chatPath}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.text();
        throw new Error(`${config.type} API error (${res.status}): ${err}`);
      }

      const data = (await res.json()) as {
        choices?: Array<{ message: { content: string } }>;
        message?: { content: string };
      };

      // OpenAI format
      if (data.choices && data.choices.length > 0) {
        return data.choices[0].message.content;
      }

      // Ollama format
      if (data.message) {
        return data.message.content;
      }

      throw new Error("Unexpected response format from LLM provider");
    },
  };
}

/**
 * Create an LLM provider from config.
 */
export function createProvider(config: ProviderConfig): LLMProvider {
  switch (config.type) {
    case "anthropic":
      return createAnthropicProvider(config);
    case "openai":
      return createOpenAIProvider(config);
    case "ollama":
      return createOpenAIProvider(config);
    default:
      throw new Error(`Unknown provider type: ${config.type}`);
  }
}

/**
 * Auto-detect provider from environment variables.
 */
export function autoDetectProvider(): ProviderConfig | null {
  if (process.env.ANTHROPIC_API_KEY) {
    return {
      type: "anthropic",
      model: process.env.KRAIT_MODEL || "claude-sonnet-4-20250514",
      apiKey: process.env.ANTHROPIC_API_KEY,
    };
  }

  if (process.env.OPENAI_API_KEY) {
    return {
      type: "openai",
      model: process.env.KRAIT_MODEL || "gpt-4o",
      apiKey: process.env.OPENAI_API_KEY,
    };
  }

  // Check if Ollama is likely running
  if (process.env.OLLAMA_HOST || process.env.KRAIT_PROVIDER === "ollama") {
    return {
      type: "ollama",
      model: process.env.KRAIT_MODEL || "llama3.1",
      baseUrl: process.env.OLLAMA_HOST || "http://localhost:11434",
    };
  }

  return null;
}
