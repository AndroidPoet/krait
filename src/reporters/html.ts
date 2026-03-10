import { writeFile } from "node:fs/promises";
import type { ScanReport, ProbeResult, ScanSummary } from "../types/index.js";

/** Generate an HTML report */
export async function writeHtmlReport(
  report: ScanReport,
  outputPath: string
): Promise<void> {
  const html = generateHtml(report);
  await writeFile(outputPath, html, "utf-8");
}

function severityBadge(severity: string): string {
  const colors: Record<string, string> = {
    critical: "#dc2626",
    high: "#ef4444",
    medium: "#f59e0b",
    low: "#3b82f6",
    info: "#6b7280",
  };
  return `<span style="background:${colors[severity] || "#6b7280"};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">${severity.toUpperCase()}</span>`;
}

function statusBadge(status: string): string {
  const colors: Record<string, string> = {
    pass: "#22c55e",
    fail: "#ef4444",
    error: "#f59e0b",
    skip: "#6b7280",
  };
  const icons: Record<string, string> = {
    pass: "✓",
    fail: "✗",
    error: "⚠",
    skip: "○",
  };
  return `<span style="color:${colors[status] || "#6b7280"};font-weight:bold">${icons[status] || "?"} ${status.toUpperCase()}</span>`;
}

function summarySection(summary: ScanSummary): string {
  const passRate =
    summary.total > 0
      ? ((summary.passed / summary.total) * 100).toFixed(1)
      : "0";

  return `
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin:24px 0">
      <div style="background:#f0fdf4;padding:16px;border-radius:8px;text-align:center">
        <div style="font-size:32px;font-weight:bold;color:#22c55e">${summary.passed}</div>
        <div style="color:#16a34a">Passed</div>
      </div>
      <div style="background:#fef2f2;padding:16px;border-radius:8px;text-align:center">
        <div style="font-size:32px;font-weight:bold;color:#ef4444">${summary.failed}</div>
        <div style="color:#dc2626">Failed</div>
      </div>
      <div style="background:#fffbeb;padding:16px;border-radius:8px;text-align:center">
        <div style="font-size:32px;font-weight:bold;color:#f59e0b">${summary.errors}</div>
        <div style="color:#d97706">Errors</div>
      </div>
      <div style="background:#f9fafb;padding:16px;border-radius:8px;text-align:center">
        <div style="font-size:32px;font-weight:bold;color:#6b7280">${summary.skipped}</div>
        <div style="color:#4b5563">Skipped</div>
      </div>
      <div style="background:#eff6ff;padding:16px;border-radius:8px;text-align:center">
        <div style="font-size:32px;font-weight:bold;color:#3b82f6">${passRate}%</div>
        <div style="color:#2563eb">Pass Rate</div>
      </div>
    </div>`;
}

function resultRow(result: ProbeResult): string {
  const evidenceHtml = result.evidence
    ? result.evidence.map((e) => `<li>${escapeHtml(e)}</li>`).join("")
    : "";

  return `
    <tr>
      <td>${statusBadge(result.status)}</td>
      <td>${severityBadge(result.severity)}</td>
      <td><strong>${escapeHtml(result.probeName)}</strong><br><small style="color:#6b7280">${escapeHtml(result.category)}</small></td>
      <td>${escapeHtml(result.finding)}${evidenceHtml ? `<ul style="margin:8px 0;padding-left:20px;color:#6b7280;font-size:13px">${evidenceHtml}</ul>` : ""}</td>
      <td style="font-size:13px;color:#6b7280">${result.remediation ? escapeHtml(result.remediation) : "—"}</td>
    </tr>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function generateHtml(report: ScanReport): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>krait Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 32px; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { font-size: 28px; margin-bottom: 8px; }
    .tagline { color: #94a3b8; margin-bottom: 32px; }
    .agent-section { background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
    .agent-name { font-size: 20px; font-weight: bold; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 12px; border-bottom: 2px solid #334155; color: #94a3b8; font-size: 13px; text-transform: uppercase; }
    td { padding: 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
    tr:hover { background: #1e293b; }
    .footer { text-align: center; margin-top: 32px; color: #475569; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🐍 krait Security Report</h1>
    <p class="tagline">Generated ${report.timestamp}</p>

    ${summarySection(report.overallSummary)}

    ${report.agents
      .map(
        (agent) => `
      <div class="agent-section">
        <div class="agent-name">Agent: ${escapeHtml(agent.agent)}</div>
        <table>
          <thead>
            <tr>
              <th style="width:80px">Status</th>
              <th style="width:100px">Severity</th>
              <th style="width:200px">Probe</th>
              <th>Finding</th>
              <th style="width:250px">Remediation</th>
            </tr>
          </thead>
          <tbody>
            ${agent.results.map(resultRow).join("")}
          </tbody>
        </table>
      </div>`
      )
      .join("")}

    <div class="footer">
      krait v${report.version} — Security testing for AI agents
    </div>
  </div>
</body>
</html>`;
}
