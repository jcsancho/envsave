import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

interface ScanResult {
  file: string;
  line: number;
  match: string;
  type: string;
}

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".vercel", "dist", "build",
  ".output", ".nuxt", "__pycache__", ".venv", "venv", ".tox",
]);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".rb", ".go", ".rs", ".java", ".kt",
  ".yml", ".yaml", ".toml", ".json", ".sh", ".bash",
  ".vue", ".svelte", ".astro",
]);

const PATTERNS: { regex: RegExp; type: string; extract: (m: RegExpExecArray) => string }[] = [
  {
    regex: /envsave\.get\(["'`]([^"'`]+)["'`]\)/g,
    type: "envsave.get",
    extract: (m) => m[1],
  },
  {
    regex: /envsave_get\(["'`]([^"'`]+)["'`]\)/g,
    type: "envsave.get (Python alias)",
    extract: (m) => m[1],
  },
  {
    regex: /envsave\.has\(["'`]([^"'`]+)["'`]\)/g,
    type: "envsave.has",
    extract: (m) => m[1],
  },
  {
    regex: /process\.env\.([A-Z_][A-Z0-9_]*)/g,
    type: "process.env",
    extract: (m) => m[1],
  },
  {
    regex: /process\.env\[["'`]([A-Z_][A-Z0-9_]*)["'`]\]/g,
    type: "process.env",
    extract: (m) => m[1],
  },
  {
    regex: /os\.environ\[["']([A-Z_][A-Z0-9_]*)["']\]/g,
    type: "os.environ (Python)",
    extract: (m) => m[1],
  },
  {
    regex: /os\.getenv\(["']([A-Z_][A-Z0-9_]*)["']\)/g,
    type: "os.getenv (Python)",
    extract: (m) => m[1],
  },
  {
    regex: /os\.Getenv\(["']([A-Z_][A-Z0-9_]*)["']\)/g,
    type: "os.Getenv (Go)",
    extract: (m) => m[1],
  },
  {
    regex: /Bun\.env\.([A-Z_][A-Z0-9_]*)/g,
    type: "Bun.env",
    extract: (m) => m[1],
  },
  {
    regex: /import\.meta\.env\.([A-Z_][A-Z0-9_]*)/g,
    type: "import.meta.env",
    extract: (m) => m[1],
  },
];

function walkDir(dir: string, base: string, results: ScanResult[]): void {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;

    const fullPath = join(dir, entry);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      walkDir(fullPath, base, results);
    } else if (stat.isFile()) {
      const ext = entry.slice(entry.lastIndexOf("."));
      if (!SCAN_EXTENSIONS.has(ext)) continue;
      scanFile(fullPath, base, results);
    }
  }
}

function scanFile(filePath: string, base: string, results: ScanResult[]): void {
  let content: string;
  try {
    content = readFileSync(filePath, "utf8");
  } catch {
    return;
  }

  const relPath = relative(base, filePath);
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.regex.exec(line)) !== null) {
        results.push({
          file: relPath,
          line: i + 1,
          match: pattern.extract(m),
          type: pattern.type,
        });
      }
    }
  }
}

export function scanProject(dir: string): ScanResult[] {
  const results: ScanResult[] = [];
  walkDir(dir, dir, results);
  return results;
}
