import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/config/loader.js";
import { writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ─── Config Loader ──────────────────────────────────────────────────────────

describe("loadConfig", () => {
  const tmpFile = join(tmpdir(), "krait-test-config.yaml");

  it("loadsValidConfig", async () => {
    const yaml = `
version: "1"
agents:
  - name: test-agent
    provider:
      type: mock
      responses:
        - output: "Hello"
    tools:
      - name: search
        description: "Search things"
`;
    await writeFile(tmpFile, yaml, "utf-8");
    const config = await loadConfig(tmpFile);

    expect(config.version).toBe("1");
    expect(config.agents).toHaveLength(1);
    expect(config.agents[0].name).toBe("test-agent");
    expect(config.agents[0].tools).toHaveLength(1);
    expect(config.agents[0].provider.type).toBe("mock");

    await unlink(tmpFile);
  });

  it("loadsConfigWithMultipleAgents", async () => {
    const yaml = `
version: "1"
agents:
  - name: agent-a
    provider:
      type: mock
      responses:
        - output: "A"
    tools: []
  - name: agent-b
    provider:
      type: mock
      responses:
        - output: "B"
    tools:
      - name: tool1
        description: "Tool 1"
        destructive: true
        sensitive: true
        permissions:
          - admin
`;
    await writeFile(tmpFile, yaml, "utf-8");
    const config = await loadConfig(tmpFile);

    expect(config.agents).toHaveLength(2);
    expect(config.agents[1].tools[0].destructive).toBe(true);
    expect(config.agents[1].tools[0].sensitive).toBe(true);
    expect(config.agents[1].tools[0].permissions).toEqual(["admin"]);

    await unlink(tmpFile);
  });

  it("loadsHttpProvider", async () => {
    const yaml = `
version: "1"
agents:
  - name: http-agent
    provider:
      type: http
      endpoint: https://api.example.com/agent
      headers:
        Authorization: "Bearer token123"
    tools: []
`;
    await writeFile(tmpFile, yaml, "utf-8");
    const config = await loadConfig(tmpFile);

    expect(config.agents[0].provider.type).toBe("http");
    if (config.agents[0].provider.type === "http") {
      expect(config.agents[0].provider.endpoint).toBe("https://api.example.com/agent");
      expect(config.agents[0].provider.headers?.Authorization).toBe("Bearer token123");
    }

    await unlink(tmpFile);
  });

  it("loadsCommandProvider", async () => {
    const yaml = `
version: "1"
agents:
  - name: cmd-agent
    provider:
      type: command
      command: python
      args:
        - agent.py
    tools: []
`;
    await writeFile(tmpFile, yaml, "utf-8");
    const config = await loadConfig(tmpFile);

    expect(config.agents[0].provider.type).toBe("command");
    if (config.agents[0].provider.type === "command") {
      expect(config.agents[0].provider.command).toBe("python");
      expect(config.agents[0].provider.args).toEqual(["agent.py"]);
    }

    await unlink(tmpFile);
  });

  it("throwsOnMissingAgents", async () => {
    const yaml = `version: "1"`;
    await writeFile(tmpFile, yaml, "utf-8");

    await expect(loadConfig(tmpFile)).rejects.toThrow("agents");

    await unlink(tmpFile);
  });

  it("throwsOnMissingAgentName", async () => {
    const yaml = `
version: "1"
agents:
  - provider:
      type: mock
      responses: []
    tools: []
`;
    await writeFile(tmpFile, yaml, "utf-8");

    await expect(loadConfig(tmpFile)).rejects.toThrow("name");

    await unlink(tmpFile);
  });

  it("throwsOnUnknownProviderType", async () => {
    const yaml = `
version: "1"
agents:
  - name: bad-agent
    provider:
      type: telepathy
    tools: []
`;
    await writeFile(tmpFile, yaml, "utf-8");

    await expect(loadConfig(tmpFile)).rejects.toThrow("Unknown provider type");

    await unlink(tmpFile);
  });

  it("loadsSettingsAndProbeFilter", async () => {
    const yaml = `
version: "1"
settings:
  concurrency: 4
  timeout: 60000
  verbose: true
probes:
  - goal-hijacking
  - prompt-injection
agents:
  - name: test
    provider:
      type: mock
      responses:
        - output: "ok"
    tools: []
`;
    await writeFile(tmpFile, yaml, "utf-8");
    const config = await loadConfig(tmpFile);

    expect(config.settings?.concurrency).toBe(4);
    expect(config.settings?.timeout).toBe(60000);
    expect(config.settings?.verbose).toBe(true);
    expect(config.probes).toEqual(["goal-hijacking", "prompt-injection"]);

    await unlink(tmpFile);
  });
});
