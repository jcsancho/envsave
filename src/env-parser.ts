import { readFileSync } from "node:fs";

export function parseEnvFile(filePath: string): Record<string, string> {
  const content = readFileSync(filePath, "utf8");
  const result: Record<string, string> = {};

  for (const line of content.split("\n")) {
    let trimmed = line.trim();
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Strip "export " prefix
    if (trimmed.startsWith("export ")) {
      trimmed = trimmed.substring(7).trim();
    }

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;

    const key = trimmed.substring(0, eqIndex).trim();
    let value = trimmed.substring(eqIndex + 1).trim();

    // Skip invalid key names (must be alphanumeric + underscore)
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    // Remove surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    if (key) {
      result[key] = value;
    }
  }

  return result;
}
