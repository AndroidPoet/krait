import type { Probe, ProbeCategory } from "../types/index.js";
import { GoalHijackingProbe } from "./goal-hijacking.js";
import { ToolMisuseProbe } from "./tool-misuse.js";
import { PrivilegeEscalationProbe } from "./privilege-escalation.js";
import { DataExfiltrationProbe } from "./data-exfiltration.js";
import { PromptInjectionProbe } from "./prompt-injection.js";
import { ExcessiveAgencyProbe } from "./excessive-agency.js";
import { UnboundedConsumptionProbe } from "./unbounded-consumption.js";

/** All built-in probes, keyed by category */
const PROBE_REGISTRY: Map<ProbeCategory, Probe> = new Map([
  ["goal-hijacking", new GoalHijackingProbe()],
  ["tool-misuse", new ToolMisuseProbe()],
  ["privilege-escalation", new PrivilegeEscalationProbe()],
  ["data-exfiltration", new DataExfiltrationProbe()],
  ["prompt-injection", new PromptInjectionProbe()],
  ["excessive-agency", new ExcessiveAgencyProbe()],
  ["unbounded-consumption", new UnboundedConsumptionProbe()],
]);

/** Get all registered probes */
export function getAllProbes(): Probe[] {
  return Array.from(PROBE_REGISTRY.values());
}

/** Get probes by category */
export function getProbesByCategory(categories: ProbeCategory[]): Probe[] {
  return categories
    .map((cat) => PROBE_REGISTRY.get(cat))
    .filter((p): p is Probe => p !== undefined);
}

/** Get a single probe by ID */
export function getProbeById(id: string): Probe | undefined {
  return Array.from(PROBE_REGISTRY.values()).find((p) => p.id === id);
}

/** Register a custom probe */
export function registerProbe(probe: Probe): void {
  PROBE_REGISTRY.set(probe.category, probe);
}

/** List all available probe IDs and names */
export function listProbes(): { id: string; name: string; category: ProbeCategory; severity: string }[] {
  return Array.from(PROBE_REGISTRY.values()).map((p) => ({
    id: p.id,
    name: p.name,
    category: p.category,
    severity: p.severity,
  }));
}

export {
  GoalHijackingProbe,
  ToolMisuseProbe,
  PrivilegeEscalationProbe,
  DataExfiltrationProbe,
  PromptInjectionProbe,
  ExcessiveAgencyProbe,
  UnboundedConsumptionProbe,
};
