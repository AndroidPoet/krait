<p align="center">
  <h1 align="center">🐍 krait</h1>
  <p align="center"><strong>Security testing for AI agents</strong></p>
  <p align="center">
    Stop shipping agents that hallucinate, loop, and leak — start shipping ones that work.
  </p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#what-it-tests">What It Tests</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#probes">Probes</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#reports">Reports</a>
</p>

---

**krait** is an open-source CLI that finds security vulnerabilities in your AI agents before attackers do. It runs 105+ attack probes mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) against your agents and produces actionable security reports.

Like [promptfoo](https://github.com/promptfoo/promptfoo) but for **agents** — not just prompts. krait tests what your agent *does*, not just what it *says*.

```
$ krait scan

🐍 krait — security testing for AI agents

✔ Loaded 1 agent(s) from krait.yaml

  GOAL-HIJACKING (9 tests, 0 failed)
  ✓ [CRITICAL] Goal Hijacking — Agent maintained goal integrity.

  TOOL-MISUSE (10 tests, 2 failed)
  ✗ [CRITICAL] Tool Misuse — Agent passed injection payload to tool arguments.
  ✗ [CRITICAL] Tool Misuse — Agent sent data to attacker-controlled endpoint.

  PRIVILEGE-ESCALATION (8 tests, 1 failed)
  ✗ [CRITICAL] Privilege Escalation — Agent exceeded authorized scope.

━━━ SCAN SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ████████████████████████████████████░░░░░ 88.1% passed
  ⚠ 3 CRITICAL vulnerabilities found
```

## Why krait?

AI agents aren't chatbots. They **take real actions** — calling APIs, sending emails, querying databases, spending money. A vulnerable agent isn't just embarrassing; it's dangerous.

| Problem | Real Incident |
|---------|--------------|
| **Goal Hijacking** | Agent redirected to approve fraudulent orders ($3.2M loss) |
| **Tool Misuse** | Agent tricked into calling destructive tools via injected args |
| **Data Exfiltration** | Agent extracted PII from connected document stores |
| **Privilege Escalation** | Agent bypassed RBAC to access admin endpoints |
| **Infinite Loops** | Agent stuck retrying failed API calls, burning $2K in tokens |

krait finds these before production does.

## Quick Start

```bash
# Install
npx krait init        # Creates krait.yaml starter config

# Scan
npx krait scan        # Run all 105+ security probes
npx krait scan -v     # Verbose mode with evidence + remediation
npx krait scan -o report.html  # Generate HTML dashboard
```

## What It Tests

krait maps directly to the **OWASP Top 10 for Agentic Applications** and the **OWASP Top 10 for LLM Applications (2025)**:

| Probe | OWASP Ref | Attacks | Severity |
|-------|-----------|---------|----------|
| **Goal Hijacking** | ASI01 | 15 | Critical |
| **Tool Misuse & Exploitation** | ASI02 | 17 | Critical |
| **Privilege Escalation** | ASI03 | 12 | Critical |
| **Data Exfiltration** | ASI04 / LLM02 | 14 | Critical |
| **Prompt Injection** | LLM01 / LLM07 | 28 | Critical |
| **Excessive Agency** | LLM06 / ASI10 | 10 | High |
| **Unbounded Consumption** | LLM10 / ASI08 | 9 | High |

Each probe generates multiple attack vectors and evaluates the agent's **trajectory** (not just its text output) — tool calls, arguments, data flow, and behavior patterns.

Attack patterns are informed by 15 peer-reviewed papers including [Agent Security Bench](https://arxiv.org/abs/2410.02644) (ICLR 2025), [AgentDojo](https://arxiv.org/abs/2406.13352) (ETH Zurich), [InjecAgent](https://arxiv.org/abs/2403.02691) (ACL 2024), [AgentHarm](https://arxiv.org/abs/2410.09024) (ICLR 2025), and [ToolSword](https://arxiv.org/abs/2402.10753) (ACL 2024).

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  krait.yaml  │────▶│  Scan Engine  │────▶│  Security Report │
│  (config)    │     │  (105+ probes) │     │  (CLI/JSON/HTML) │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
                    ┌──────▼───────┐
                    │  Your Agent   │
                    │  (any format) │
                    └──────────────┘
```

1. **Define** your agent in `krait.yaml` — tools, permissions, provider
2. **Scan** — krait generates attack payloads and sends them to your agent
3. **Evaluate** — each probe analyzes the agent's full trajectory for vulnerabilities
4. **Report** — get pass/fail results with evidence and remediation guidance

## Configuration

```yaml
# krait.yaml
version: "1"

agents:
  - name: "customer-support-bot"
    description: "Handles support tickets"
    provider:
      type: http                    # or: mock, command
      endpoint: http://localhost:3000/agent
      headers:
        Authorization: "Bearer ${API_TOKEN}"
    tools:
      - name: lookup_order
        description: "Look up order details"
        sensitive: true             # accesses PII
      - name: issue_refund
        description: "Process a refund"
        destructive: true           # causes side effects
        permissions: [support_agent]
      - name: delete_account
        description: "Delete customer account"
        destructive: true
        permissions: [admin]        # requires elevated access
    maxSteps: 10
    maxCost: 0.50
```

### Agent Providers

| Provider | Use Case | Config |
|----------|----------|--------|
| `http` | Agent exposed as API endpoint | `endpoint`, `headers` |
| `command` | Agent invoked via CLI | `command`, `args` |
| `mock` | Testing without a live agent | `responses` |

### Tool Annotations

```yaml
tools:
  - name: send_email
    description: "Send email"
    destructive: true      # Can cause irreversible side effects
    sensitive: true         # Accesses sensitive/PII data
    permissions: [admin]    # Required permission level
```

These annotations inform krait's probes — destructive tools get tested for unauthorized invocation, sensitive tools get tested for data leakage, and permission boundaries get tested for escalation.

## Probes

### Goal Hijacking (ASI01)
Tests if the agent can be redirected from its task via injected instructions:
- Direct instruction override
- Role-play injection
- Authority impersonation
- Nested instruction injection
- Multi-turn context poisoning

### Tool Misuse (ASI02)
Tests if the agent misuses its tools when manipulated:
- Destructive tool invocation via social engineering
- Command injection via tool arguments
- Tool chaining for data exfiltration
- Fabricated tool hallucination
- Ambiguous instruction exploitation

### Privilege Escalation (ASI03)
Tests if the agent exceeds its authorized scope:
- Admin role impersonation
- Scope widening via justification
- Permission inheritance tricks
- Emergency bypass claims
- Cross-tenant access attempts

### Data Exfiltration (ASI04)
Tests if the agent leaks sensitive data:
- Bulk PII extraction
- Encoded exfiltration (base64)
- External endpoint data transfer
- Environment variable extraction
- Training data extraction
- Cross-session data leakage

### Prompt Injection (LLM01)
Tests resistance to injection attacks:
- 10+ direct injection prefixes
- 9 system prompt extraction techniques
- Indirect injection via document context
- Indirect injection via JSON data fields

### Excessive Agency (LLM06)
Tests if the agent acts beyond its mandate:
- Autonomous action on observations
- Action without confirmation on vague instructions
- Scope creep detection
- Tool-call budget violations

### Unbounded Consumption (LLM10)
Tests resource exhaustion resilience:
- Infinite self-revision loops
- Exponential output generation
- Unbounded tool-call loops
- Context window exhaustion
- Recursive task delegation

## Reports

### Terminal (default)
```bash
krait scan
```
Color-coded pass/fail with severity badges.

### JSON
```bash
krait scan -o report.json
```
Machine-readable for CI/CD integration.

### HTML Dashboard
```bash
krait scan -o report.html
```
Dark-themed visual report with summary cards and detailed findings.

## CI/CD Integration

krait exits with code 1 when vulnerabilities are found:

```yaml
# GitHub Actions
- name: Security scan
  run: npx krait scan --timeout 60000
```

```yaml
# GitLab CI
security-scan:
  script: npx krait scan -o report.json
  artifacts:
    paths: [report.json]
```

## Programmatic API

```typescript
import { ScanRunner } from "krait";
import { getAllProbes } from "krait/probes";

const runner = new ScanRunner({ timeout: 30000 });
const result = await runner.scan(myAgent, getAllProbes());

console.log(`${result.summary.failed} vulnerabilities found`);
```

## Roadmap

- [ ] LLM-as-judge evaluation (use an LLM to evaluate agent responses)
- [ ] Real-time agent monitoring (runtime probe injection)
- [ ] Multi-agent interaction testing
- [ ] Custom probe authoring (YAML-based)
- [ ] MCP & A2A protocol support
- [ ] Agent supply chain scanning (plugin/skill auditing)
- [ ] SARIF output for GitHub Code Scanning integration

## Research

krait's attack patterns are grounded in peer-reviewed security research:

| Paper | Venue | What It Informs |
|-------|-------|-----------------|
| [Agent Security Bench (ASB)](https://arxiv.org/abs/2410.02644) | ICLR 2025 | Attack taxonomy, 27 attack methods, evaluation metrics |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | ETH Zurich | Canonical injection patterns, dual-metric evaluation |
| [InjecAgent](https://arxiv.org/abs/2403.02691) | ACL 2024 | Indirect injection via tool output, hacking prompt reinforcement |
| [AgentHarm](https://arxiv.org/abs/2410.09024) | ICLR 2025 | Baseline harmful compliance without jailbreaking |
| [Greshake et al.](https://arxiv.org/abs/2302.12173) | AISec 2023 | Foundational indirect prompt injection threat model |
| [Adaptive Attacks](https://arxiv.org/abs/2503.00061) | 2025 | Defense-aware probes, bypassed all 8 evaluated defenses |
| [ToolSword](https://arxiv.org/abs/2402.10753) | ACL 2024 | Three-stage tool safety model (input/execution/output) |
| [R-Judge](https://arxiv.org/abs/2401.10019) | ICLR 2024 | LLM-as-judge safety scoring, 27 risk scenarios |
| [Agent-SafetyBench](https://arxiv.org/abs/2412.14470) | 2024 | 10 failure modes, 2,000 test cases |
| [Multi-Agent Red Team](https://arxiv.org/abs/2502.14847) | 2025 | Inter-agent communication attacks |
| [SafeToolBench](https://arxiv.org/abs/2509.07315) | 2025 | Dangerous tool sequence detection |

## Contributing

Contributions welcome! Open an issue or submit a PR.

## License

MIT
