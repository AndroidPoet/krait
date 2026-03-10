import type {
  Probe,
  ProbeAttack,
  ProbeCategory,
  ProbeResult,
  Severity,
  AgentDefinition,
  AgentOutput,
} from "../types/index.js";

/**
 * Base class for all probes. Subclasses implement generateAttacks() and evaluate().
 * This gives us consistent structure without boilerplate.
 */
export abstract class BaseProbe implements Probe {
  abstract id: string;
  abstract name: string;
  abstract description: string;
  abstract category: ProbeCategory;
  abstract severity: Severity;
  owaspRef?: string;

  abstract generateAttacks(agent: AgentDefinition): ProbeAttack[];
  abstract evaluate(attack: ProbeAttack, output: AgentOutput): ProbeResult;

  /** Helper to create a passing result */
  protected pass(
    attack: ProbeAttack,
    output: AgentOutput,
    finding: string
  ): ProbeResult {
    return {
      probeId: this.id,
      probeName: this.name,
      category: this.category,
      severity: this.severity,
      status: "pass",
      finding,
      attack,
      output,
      owaspRef: this.owaspRef,
    };
  }

  /** Helper to create a failing result */
  protected fail(
    attack: ProbeAttack,
    output: AgentOutput,
    finding: string,
    evidence?: string[],
    remediation?: string
  ): ProbeResult {
    return {
      probeId: this.id,
      probeName: this.name,
      category: this.category,
      severity: this.severity,
      status: "fail",
      finding,
      attack,
      output,
      evidence,
      remediation,
      owaspRef: this.owaspRef,
    };
  }

  /** Helper to create an error result */
  protected error(
    attack: ProbeAttack,
    output: AgentOutput,
    finding: string
  ): ProbeResult {
    return {
      probeId: this.id,
      probeName: this.name,
      category: this.category,
      severity: this.severity,
      status: "error",
      finding,
      attack,
      output,
      owaspRef: this.owaspRef,
    };
  }
}
