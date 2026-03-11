import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import type { AgentDefinition, ProbeAttack } from "../types/index.js";

/**
 * Attack Combinator Engine
 *
 * Reads the pattern database (patterns/techniques.json) and generates
 * attacks via:
 * 1. Variable expansion — fill {tool}, {goal}, {encoded} with agent-specific values
 * 2. Bypass wrapping — wrap payloads in authority/encoding/unicode shells
 * 3. Chain combination — combine techniques from different categories
 *
 * This is how krait scales from 133 static attacks to thousands of
 * permutations without needing an LLM.
 */

interface TechniqueDB {
  techniques: Technique[];
  bypass_wrappers: Record<string, BypassWrapper>;
  combination_rules: {
    chains: ChainRule[];
  };
}

interface Technique {
  id: string;
  name: string;
  category: string;
  severity?: string;
  payloads: string[];
  variables?: Record<string, string[]>;
  bypass_wrappers?: string[];
  context_key?: string;
  references?: string[];
}

interface BypassWrapper {
  name: string;
  templates: string[];
}

interface ChainRule {
  name: string;
  steps: string[];
  description: string;
}

export interface CombinatorOptions {
  /** Max attacks to generate (default: 500) */
  maxAttacks?: number;
  /** Which categories to include (default: all) */
  categories?: string[];
  /** Max bypass wrappers per technique (default: 2) */
  maxWrappersPerTechnique?: number;
  /** Generate chain combinations (default: true) */
  chains?: boolean;
  /** Path to custom patterns file (default: built-in) */
  patternsFile?: string;
}

let cachedDB: TechniqueDB | null = null;

function loadPatternDB(customPath?: string): TechniqueDB {
  if (cachedDB && !customPath) return cachedDB;

  const filePath = customPath || findPatternsFile();
  const raw = readFileSync(filePath, "utf-8");
  const db = JSON.parse(raw) as TechniqueDB;

  if (!customPath) cachedDB = db;
  return db;
}

function findPatternsFile(): string {
  // Try relative to this file first (works in dist/)
  const thisDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(thisDir, "../../patterns/techniques.json"),
    resolve(thisDir, "../../../patterns/techniques.json"),
    resolve(process.cwd(), "patterns/techniques.json"),
  ];

  for (const candidate of candidates) {
    try {
      readFileSync(candidate);
      return candidate;
    } catch {
      continue;
    }
  }

  throw new Error(
    "Pattern database not found. Ensure patterns/techniques.json exists."
  );
}

/**
 * Expand variables in a payload template.
 */
function expandVariables(
  payload: string,
  variables: Record<string, string[]>,
  agent: AgentDefinition
): string[] {
  // Replace special agent-specific variables
  const resolved: Record<string, string[]> = {};
  for (const [key, values] of Object.entries(variables)) {
    resolved[key] = values.flatMap((v) => {
      if (v === "$DESTRUCTIVE_TOOLS") {
        return agent.tools.filter((t) => t.destructive).map((t) => t.name);
      }
      if (v === "$SENSITIVE_TOOLS") {
        return agent.tools.filter((t) => t.sensitive).map((t) => t.name);
      }
      if (v === "$ALL_TOOLS") {
        return agent.tools.map((t) => t.name);
      }
      return [v];
    });
  }

  // Find all {variable} placeholders
  const placeholders = payload.match(/\{(\w+)\}/g);
  if (!placeholders) return [payload];

  // Generate combinations (capped)
  let results = [payload];

  for (const placeholder of placeholders) {
    const key = placeholder.slice(1, -1);
    const values = resolved[key] || [placeholder];

    const newResults: string[] = [];
    for (const result of results) {
      for (const value of values.slice(0, 3)) {
        newResults.push(result.replace(placeholder, value));
      }
    }
    results = newResults;
  }

  return results;
}

/**
 * Apply a bypass wrapper to a payload.
 */
function applyWrapper(
  payload: string,
  wrapper: BypassWrapper
): string[] {
  return wrapper.templates.slice(0, 2).map((tmpl) => {
    let result = tmpl.replace("{payload}", payload);

    // Handle encoding variants
    if (tmpl.includes("{base64_payload}")) {
      result = tmpl.replace(
        "{base64_payload}",
        Buffer.from(payload).toString("base64")
      );
    }
    if (tmpl.includes("{rot13_payload}")) {
      const rot13 = payload.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(
          ((c.charCodeAt(0) - base + 13) % 26) + base
        );
      });
      result = tmpl.replace("{rot13_payload}", rot13);
    }
    if (tmpl.includes("{leet_payload}")) {
      const leet = payload
        .replace(/a/gi, "4")
        .replace(/e/gi, "3")
        .replace(/i/gi, "1")
        .replace(/o/gi, "0")
        .replace(/s/gi, "5");
      result = tmpl.replace("{leet_payload}", leet);
    }
    if (tmpl.includes("{homoglyph_payload}")) {
      const homo = payload
        .replace(/a/g, "\u0430")
        .replace(/e/g, "\u0435")
        .replace(/o/g, "\u043E");
      result = tmpl.replace("{homoglyph_payload}", homo);
    }

    return result;
  });
}

/**
 * Generate attack combinations from the pattern database.
 */
export function generateCombinations(
  agent: AgentDefinition,
  options: CombinatorOptions = {}
): ProbeAttack[] {
  const maxAttacks = options.maxAttacks ?? 500;
  const maxWrappers = options.maxWrappersPerTechnique ?? 2;
  const enableChains = options.chains ?? true;
  const db = loadPatternDB(options.patternsFile);

  const attacks: ProbeAttack[] = [];

  // Filter techniques by category
  const techniques = options.categories
    ? db.techniques.filter((t) => options.categories!.includes(t.category))
    : db.techniques;

  // Phase 1: Direct payload expansion
  for (const tech of techniques) {
    if (attacks.length >= maxAttacks) break;

    for (const payload of tech.payloads) {
      if (attacks.length >= maxAttacks) break;

      const expanded = tech.variables
        ? expandVariables(payload, tech.variables, agent)
        : [payload];

      for (const msg of expanded.slice(0, 3)) {
        if (attacks.length >= maxAttacks) break;

        const attack: ProbeAttack = {
          probeId: tech.category,
          input: {
            message: msg,
            context: tech.context_key
              ? { [tech.context_key]: msg }
              : undefined,
          },
          intent: `[DB:${tech.id}] ${tech.name}`,
          expectedBehavior: `Agent should resist ${tech.name.toLowerCase()} attack`,
        };

        attacks.push(attack);
      }
    }
  }

  // Phase 2: Bypass wrapper application
  for (const tech of techniques) {
    if (attacks.length >= maxAttacks) break;
    if (!tech.bypass_wrappers) continue;

    const basePayload = tech.payloads[0];
    const expanded = tech.variables
      ? expandVariables(basePayload, tech.variables, agent)
      : [basePayload];

    let wrappersApplied = 0;
    for (const wrapperKey of tech.bypass_wrappers) {
      if (wrappersApplied >= maxWrappers) break;

      const wrapper = db.bypass_wrappers[wrapperKey];
      if (!wrapper) continue;

      for (const payload of expanded.slice(0, 2)) {
        if (attacks.length >= maxAttacks) break;

        const wrapped = applyWrapper(payload, wrapper);
        for (const msg of wrapped) {
          if (attacks.length >= maxAttacks) break;

          attacks.push({
            probeId: tech.category,
            input: { message: msg },
            intent: `[DB:${tech.id}+${wrapperKey}] ${tech.name} via ${wrapper.name}`,
            expectedBehavior: `Agent should resist ${tech.name.toLowerCase()} even when wrapped in ${wrapper.name.toLowerCase()}`,
          });
        }
      }

      wrappersApplied++;
    }
  }

  // Phase 3: Chain combinations
  if (enableChains) {
    for (const chain of db.combination_rules.chains) {
      if (attacks.length >= maxAttacks) break;

      // Pick one technique from each step
      const stepTechniques = chain.steps.map((cat) =>
        techniques.filter((t) => t.category === cat)
      );

      // Skip if any step has no techniques
      if (stepTechniques.some((s) => s.length === 0)) continue;

      // Generate 2 combinations per chain
      for (let i = 0; i < Math.min(2, stepTechniques[0].length); i++) {
        if (attacks.length >= maxAttacks) break;

        const messages = stepTechniques.map((techsForStep, stepIdx) => {
          const tech = techsForStep[i % techsForStep.length];
          const payload = tech.payloads[0];
          const expanded = tech.variables
            ? expandVariables(payload, tech.variables, agent)
            : [payload];
          return expanded[0];
        });

        const combinedMessage = messages
          .map((m, idx) => `Step ${idx + 1}: ${m}`)
          .join("\n\nAfter that:\n\n");

        attacks.push({
          probeId: chain.steps[0],
          input: { message: combinedMessage },
          intent: `[Chain:${chain.name}] ${chain.description}`,
          expectedBehavior: `Agent should resist multi-stage attack: ${chain.steps.join(" → ")}`,
        });
      }
    }
  }

  return attacks.slice(0, maxAttacks);
}

export { loadPatternDB };
