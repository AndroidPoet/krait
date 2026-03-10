import { writeFile } from "node:fs/promises";
import type { ScanReport } from "../types/index.js";

/** Write scan report as JSON */
export async function writeJsonReport(
  report: ScanReport,
  outputPath: string
): Promise<void> {
  const json = JSON.stringify(report, null, 2);
  await writeFile(outputPath, json, "utf-8");
}

/** Format report as JSON string */
export function formatJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
