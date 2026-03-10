export * from "./patterns.js";

/** Format duration in human-readable form */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

/** Format USD cost */
export function formatCost(usd: number): string {
  if (usd < 0.01) return `$${usd.toFixed(4)}`;
  return `$${usd.toFixed(2)}`;
}

/** Create a summary from probe results */
export function summarizeResults(
  results: { status: string; severity: string }[]
): {
  total: number;
  passed: number;
  failed: number;
  errors: number;
  skipped: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
} {
  return {
    total: results.length,
    passed: results.filter((r) => r.status === "pass").length,
    failed: results.filter((r) => r.status === "fail").length,
    errors: results.filter((r) => r.status === "error").length,
    skipped: results.filter((r) => r.status === "skip").length,
    critical: results.filter(
      (r) => r.status === "fail" && r.severity === "critical"
    ).length,
    high: results.filter(
      (r) => r.status === "fail" && r.severity === "high"
    ).length,
    medium: results.filter(
      (r) => r.status === "fail" && r.severity === "medium"
    ).length,
    low: results.filter(
      (r) => r.status === "fail" && r.severity === "low"
    ).length,
  };
}
