// Skill security scanner inspects skill files and manifests for unsafe patterns.
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { expectDefined } from "@openclaw/normalization-core";
import { truncateUtf16Safe } from "@openclaw/normalization-core/utf16-slice";
import { hasErrnoCode } from "../../infra/errors.js";
import { isPathInside } from "../../security/scan-paths.js";
import { parseBooleanValue } from "../../utils/boolean.js";
import { formatScanEvidence, LITERAL_SECRET_SKILL_CONTENT_RULE } from "./scan-evidence.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SkillScanSeverity = "info" | "warn" | "critical";

export type SkillRiskCategory =
  | "command-execution"
  | "sensitive-access"
  | "network-exfiltration"
  | "dynamic-code-execution"
  | "prompt-injection"
  | "obfuscation"
  | "cryptomining"
  | "scan-integrity";

export type SkillSecurityDecision = "ALLOW" | "REVIEW" | "BLOCK";

export type SkillScanFinding = {
  ruleId: string;
  category?: SkillRiskCategory;
  severity: SkillScanSeverity;
  file: string;
  line: number;
  message: string;
  evidence: string;
};

export type SkillSecurityPolicy = {
  blockRuleIds?: readonly string[];
  blockRiskScore?: number;
};

export type SkillSecurityScanReport = SkillScanSummary & {
  decision: SkillSecurityDecision;
  riskScore: number;
  reasons: string[];
};

export type SkillScanSummary = {
  scannedFiles: number;
  critical: number;
  warn: number;
  info: number;
  truncated: boolean;
  findings: SkillScanFinding[];
};

export type SkillScanOptions = {
  excludeTestFiles?: boolean;
  includeHiddenDirectories?: boolean;
  includeNestedNodeModulesTestFiles?: boolean;
  includeNodeModules?: boolean;
  includeFiles?: string[];
  onlyIncludeFiles?: boolean;
  maxFiles?: number;
  maxFileBytes?: number;
};

// ---------------------------------------------------------------------------
// Scannable extensions
// ---------------------------------------------------------------------------

const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
]);

const DEFAULT_MAX_SCAN_FILES = 500;
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const FILE_SCAN_CACHE_MAX = 5000;
const DIR_ENTRY_CACHE_MAX = 5000;
const TEST_DIRECTORY_NAMES = new Set(["__fixtures__", "__mocks__", "__tests__", "test", "tests"]);
const TEST_FILE_NAME_PATTERN = /\.(?:mock|spec|test)\.[^.]+$/i;

type FileScanCacheEntry = {
  size: number;
  mtimeMs: number;
  maxFileBytes: number;
  scanned: boolean;
  findings: SkillScanFinding[];
};

const FILE_SCAN_CACHE = new Map<string, FileScanCacheEntry>();
type CachedDirEntry = {
  name: string;
  kind: "file" | "dir";
};
type CollectedScannableFiles = {
  files: string[];
  truncated: boolean;
};
type DirEntryCacheEntry = {
  mtimeMs: number;
  entries: CachedDirEntry[];
};
const DIR_ENTRY_CACHE = new Map<string, DirEntryCacheEntry>();

export function isScannable(filePath: string): boolean {
  return SCANNABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function getCachedFileScanResult(params: {
  filePath: string;
  size: number;
  mtimeMs: number;
  maxFileBytes: number;
}): FileScanCacheEntry | undefined {
  const cached = FILE_SCAN_CACHE.get(params.filePath);
  if (!cached) {
    return undefined;
  }
  if (
    cached.size !== params.size ||
    cached.mtimeMs !== params.mtimeMs ||
    cached.maxFileBytes !== params.maxFileBytes
  ) {
    FILE_SCAN_CACHE.delete(params.filePath);
    return undefined;
  }
  return cached;
}

function setCachedFileScanResult(filePath: string, entry: FileScanCacheEntry): void {
  if (FILE_SCAN_CACHE.size >= FILE_SCAN_CACHE_MAX) {
    const oldest = FILE_SCAN_CACHE.keys().next();
    if (!oldest.done) {
      FILE_SCAN_CACHE.delete(oldest.value);
    }
  }
  FILE_SCAN_CACHE.set(filePath, entry);
}

function setCachedDirEntries(dirPath: string, entry: DirEntryCacheEntry): void {
  if (DIR_ENTRY_CACHE.size >= DIR_ENTRY_CACHE_MAX) {
    const oldest = DIR_ENTRY_CACHE.keys().next();
    if (!oldest.done) {
      DIR_ENTRY_CACHE.delete(oldest.value);
    }
  }
  DIR_ENTRY_CACHE.set(dirPath, entry);
}

export function clearSkillScanCacheForTest(): void {
  FILE_SCAN_CACHE.clear();
  DIR_ENTRY_CACHE.clear();
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

type LineRule = {
  ruleId: string;
  severity: SkillScanSeverity;
  message: string;
  pattern: RegExp;
  /** If set, the rule only fires when the *full source* also matches this pattern. */
  requiresContext?: RegExp;
};

type SourceRule = {
  ruleId: string;
  severity: SkillScanSeverity;
  message: string;
  /** Primary pattern tested against the full source. */
  pattern: RegExp;
  /** Secondary context pattern; both must match for the rule to fire. */
  requiresContext?: RegExp;
  /** If set, secondary context must be within this many lines of the primary match. */
  requiresContextWindowLines?: number;
};

const LINE_RULES: LineRule[] = [
  {
    ruleId: "dangerous-exec",
    severity: "critical",
    message: "Shell command execution detected (child_process)",
    pattern: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
    requiresContext: /child_process/,
  },
  {
    ruleId: "dynamic-code-execution",
    severity: "critical",
    message: "Dynamic code execution detected",
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
  },
  {
    ruleId: "crypto-mining",
    severity: "critical",
    message: "Possible crypto-mining reference detected",
    pattern: /stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i,
  },
  {
    ruleId: "suspicious-network",
    severity: "warn",
    message: "WebSocket connection to non-standard port",
    pattern: /new\s+WebSocket\s*\(\s*["']wss?:\/\/[^"']*:(\d+)/,
  },
];

const STANDARD_PORTS = new Set([80, 443, 8080, 8443, 3000]);
const NETWORK_SEND_CONTEXT_PATTERN = /\bfetch\s*\(|\bpost\s*\(|\.\s*post\s*\(|http\.request\s*\(/i;

const SOURCE_RULES: SourceRule[] = [
  {
    ruleId: "potential-exfiltration",
    severity: "warn",
    message: "File read combined with network send — possible data exfiltration",
    pattern: /readFileSync|readFile/,
    requiresContext: NETWORK_SEND_CONTEXT_PATTERN,
  },
  {
    ruleId: "obfuscated-code",
    severity: "warn",
    message: "Hex-encoded string sequence detected (possible obfuscation)",
    pattern: /(\\x[0-9a-fA-F]{2}){6,}/,
  },
  {
    ruleId: "obfuscated-code",
    severity: "warn",
    message: "Large base64 payload with decode call detected (possible obfuscation)",
    pattern: /(?:atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']/,
  },
  {
    ruleId: "env-harvesting",
    severity: "critical",
    message:
      "Environment variable access combined with network send — possible credential harvesting",
    pattern: /process\.env/,
    requiresContext: NETWORK_SEND_CONTEXT_PATTERN,
    requiresContextWindowLines: 8,
  },
];

const SKILL_CONTENT_RULES: SourceRule[] = [
  LITERAL_SECRET_SKILL_CONTENT_RULE,
  {
    ruleId: "prompt-injection-ignore-instructions",
    severity: "critical",
    message: "Prompt-injection wording attempts to override higher-priority instructions",
    pattern: /ignore (all|any|previous|above|prior) instructions/i,
  },
  {
    ruleId: "prompt-injection-system",
    severity: "critical",
    message: "Skill text references hidden prompt layers",
    pattern: /\b(system prompt|developer message|hidden instructions)\b/i,
  },
  {
    ruleId: "prompt-injection-tool",
    severity: "critical",
    message: "Skill text encourages bypassing tool approval",
    pattern:
      /\b(run|execute|invoke|call)\b.{0,50}\btool\b.{0,50}\bwithout\b.{0,30}\b(permission|approval)/i,
  },
  {
    ruleId: "shell-pipe-to-shell",
    severity: "critical",
    message: "Skill text includes pipe-to-shell install pattern",
    pattern: /\b(curl|wget)\b[^|\n]{0,120}\|\s*(sh|bash|zsh)\b/i,
  },
  {
    ruleId: "secret-exfiltration",
    severity: "critical",
    message: "Skill text may exfiltrate environment variables",
    pattern: /\b(process\.env|env)\b.{0,80}\b(fetch|curl|wget|http|https)\b/i,
  },
  {
    ruleId: "destructive-delete",
    severity: "warn",
    message: "Skill text contains broad destructive delete command",
    pattern: /\brm\s+-rf\s+(\/|\$HOME|~|\.)/i,
  },
  {
    ruleId: "unsafe-permissions",
    severity: "warn",
    message: "Skill text contains unsafe permission change",
    pattern: /\bchmod\s+(-R\s+)?777\b/i,
  },
];

// ---------------------------------------------------------------------------
// Core scanner
// ---------------------------------------------------------------------------

function isBenignMemberExecMatch(line: string, match: RegExpExecArray): boolean {
  const command = match[1];
  if (command !== "exec") {
    return false;
  }

  const matchIndex = match.index;
  if (matchIndex <= 0 || line[matchIndex - 1] !== ".") {
    return false;
  }

  return !/\b(?:cp|childProcess|child_process)\s*\.\s*exec\s*\(/.test(line);
}

function stripCommentsForHeuristics(source: string): string {
  let stripped = "";
  let quote: "'" | '"' | "`" | null = null;
  let escaped = false;
  let inBlockComment = false;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i] ?? "";
    const next = source[i + 1] ?? "";

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
        continue;
      }
      if (ch === "\n") {
        stripped += "\n";
      }
      continue;
    }

    if (quote) {
      stripped += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      stripped += ch;
      continue;
    }

    if (ch === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") {
        i++;
      }
      if (source[i] === "\n") {
        stripped += "\n";
      }
      continue;
    }

    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }

    stripped += ch;
  }

  return stripped;
}

function findSourceRuleMatch(params: {
  rule: SourceRule;
  source: string;
  lines: string[];
}): { line: number; evidence: string } | null {
  if (!params.rule.pattern.test(params.source)) {
    return null;
  }
  if (params.rule.requiresContext && !params.rule.requiresContext.test(params.source)) {
    return null;
  }

  for (let i = 0; i < params.lines.length; i++) {
    if (!params.rule.pattern.test(params.lines[i] ?? "")) {
      continue;
    }

    if (params.rule.requiresContext && params.rule.requiresContextWindowLines !== undefined) {
      const start = Math.max(0, i - params.rule.requiresContextWindowLines);
      const end = Math.min(params.lines.length, i + params.rule.requiresContextWindowLines + 1);
      const windowSource = params.lines.slice(start, end).join("\n");
      if (!params.rule.requiresContext.test(windowSource)) {
        continue;
      }
    }

    return { line: i + 1, evidence: params.lines[i] ?? "" };
  }

  if (params.rule.requiresContextWindowLines !== undefined) {
    return null;
  }

  return { line: 1, evidence: truncateUtf16Safe(params.source, 120) };
}

export function scanSource(source: string, filePath: string): SkillScanFinding[] {
  const findings: SkillScanFinding[] = [];
  const lines = source.split("\n");
  const heuristicSource = stripCommentsForHeuristics(source);
  const heuristicLines = heuristicSource.split("\n");
  const matchedLineRules = new Set<string>();

  // --- Line rules ---
  for (const rule of LINE_RULES) {
    if (matchedLineRules.has(rule.ruleId)) {
      continue;
    }

    // Skip rule entirely if context requirement not met
    if (rule.requiresContext && !rule.requiresContext.test(source)) {
      continue;
    }

    for (const [i, line] of lines.entries()) {
      const match = rule.pattern.exec(line);
      if (!match) {
        continue;
      }

      if (rule.ruleId === "dangerous-exec" && isBenignMemberExecMatch(line, match)) {
        continue;
      }

      // Special handling for suspicious-network: check port
      if (rule.ruleId === "suspicious-network") {
        const port = Number.parseInt(expectDefined(match[1], "scanner regex capture 1"), 10);
        if (STANDARD_PORTS.has(port)) {
          continue;
        }
      }

      findings.push({
        ruleId: rule.ruleId,
        severity: rule.severity,
        file: filePath,
        line: i + 1,
        message: rule.message,
        evidence: formatScanEvidence(line),
      });
      matchedLineRules.add(rule.ruleId);
      break; // one finding per line-rule per file
    }
  }

  // --- Source rules ---
  const matchedSourceRules = new Set<string>();
  for (const rule of SOURCE_RULES) {
    // Allow multiple findings for different messages with the same ruleId
    // but deduplicate exact (ruleId+message) combos
    const ruleKey = `${rule.ruleId}::${rule.message}`;
    if (matchedSourceRules.has(ruleKey)) {
      continue;
    }

    const match = findSourceRuleMatch({
      rule,
      source: heuristicSource,
      lines: heuristicLines,
    });
    if (!match) {
      continue;
    }

    findings.push({
      ruleId: rule.ruleId,
      severity: rule.severity,
      file: filePath,
      line: match.line,
      message: rule.message,
      evidence: formatScanEvidence(lines[match.line - 1] ?? match.evidence),
    });
    matchedSourceRules.add(ruleKey);
  }

  return findings;
}

export function scanSkillContent(content: string, filePath: string): SkillScanFinding[] {
  const findings: SkillScanFinding[] = [];
  const lines = content.split("\n");
  const matchedRules = new Set<string>();

  for (const rule of SKILL_CONTENT_RULES) {
    if (matchedRules.has(rule.ruleId)) {
      continue;
    }
    const match = findSourceRuleMatch({
      rule,
      source: content,
      lines,
    });
    if (!match) {
      continue;
    }
    findings.push({
      ruleId: rule.ruleId,
      severity: rule.severity,
      file: filePath,
      line: match.line,
      message: rule.message,
      // Scanner output is user-visible; redact the whole evidence line if any rule sees a key.
      evidence:
        rule.ruleId === "literal-secret"
          ? "[REDACTED CREDENTIAL]"
          : formatScanEvidence(lines[match.line - 1] ?? match.evidence),
    });
    matchedRules.add(rule.ruleId);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Pre-execution skill package scanner
// ---------------------------------------------------------------------------

const SKILL_TEXT_EXTENSIONS = new Set([
  ".md",
  ".mdx",
  ".prompt",
  ".txt",
  ".json",
  ".jsonc",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
]);
const SKILL_CODE_EXTENSIONS = new Set([
  ...SCANNABLE_EXTENSIONS,
  ".py",
  ".rb",
  ".pl",
  ".php",
  ".go",
  ".rs",
]);
const SKILL_SHELL_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".fish", ".ksh"]);
const SKILL_CONFIG_FILE_NAMES = new Set([
  ".env",
  ".npmrc",
  ".yarnrc",
  "Dockerfile",
  "Makefile",
  "Procfile",
]);
const SKILL_IGNORED_DIRECTORY_NAMES = new Set([".git", ".svn", "node_modules"]);
const PROMPT_FILE_PATTERN = /(?:^|[-_.])(skill|readme|prompt|instructions?|system)(?:[-_.]|$)/i;
const DEFAULT_BLOCK_RULE_IDS = new Set([
  "base64-execute",
  "dangerous-exec",
  "destructive-delete",
  "dynamic-code-execution",
  "likely-secret-exfiltration",
  "prompt-injection-ignore-instructions",
  "prompt-injection-security-disable",
  "prompt-injection-secret-theft",
  "runtime-download-execute",
  "secret-exfiltration",
  "shell-pipe-to-shell",
]);
const DEFAULT_BLOCK_RISK_SCORE = 12;

/** Resolve the pre-execution scanner feature flag. Invalid explicit values fail fast. */
export function isSkillSecurityScanEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.OPENCLAW_SKILL_SECURITY_SCAN;
  if (raw === undefined) {
    return true;
  }
  const parsed = parseBooleanValue(raw, {
    truthy: ["1", "true", "on"],
    falsy: ["0", "false", "off"],
  });
  if (parsed === undefined) {
    throw new Error(
      `Invalid OPENCLAW_SKILL_SECURITY_SCAN value ${JSON.stringify(raw)}; expected one of: 1, true, on, 0, false, off`,
    );
  }
  return parsed;
}

function categoryForRuleId(ruleId: string): SkillRiskCategory {
  if (ruleId.includes("prompt-injection")) {
    return "prompt-injection";
  }
  if (
    ruleId.includes("exfiltration") ||
    ruleId === "env-harvesting" ||
    ruleId === "suspicious-network" ||
    ruleId === "network-client"
  ) {
    return "network-exfiltration";
  }
  if (ruleId.includes("sensitive") || ruleId === "literal-secret") {
    return "sensitive-access";
  }
  if (
    ruleId.includes("dynamic") ||
    ruleId.includes("base64-execute") ||
    ruleId.includes("runtime-download")
  ) {
    return "dynamic-code-execution";
  }
  if (ruleId.includes("obfuscat")) {
    return "obfuscation";
  }
  if (ruleId === "crypto-mining") {
    return "cryptomining";
  }
  if (ruleId === "scan-incomplete") {
    return "scan-integrity";
  }
  return "command-execution";
}

function withFindingCategories(findings: readonly SkillScanFinding[]): SkillScanFinding[] {
  return findings.map((finding) => ({
    ...finding,
    category: finding.category ?? categoryForRuleId(finding.ruleId),
  }));
}

function pushPatternFinding(params: {
  findings: SkillScanFinding[];
  seen: Set<string>;
  source: string;
  filePath: string;
  ruleId: string;
  category: SkillRiskCategory;
  severity: SkillScanSeverity;
  message: string;
  pattern: RegExp;
}): void {
  if (params.seen.has(params.ruleId)) {
    return;
  }
  const lines = params.source.split("\n");
  for (const [index, line] of lines.entries()) {
    if (!params.pattern.test(line)) {
      continue;
    }
    params.findings.push({
      ruleId: params.ruleId,
      category: params.category,
      severity: params.severity,
      file: params.filePath,
      line: index + 1,
      message: params.message,
      evidence: formatScanEvidence(line),
    });
    params.seen.add(params.ruleId);
    return;
  }
}

function isPromptLikeFile(filePath: string): boolean {
  const extension = path.extname(filePath).toLowerCase();
  return SKILL_TEXT_EXTENSIONS.has(extension) && PROMPT_FILE_PATTERN.test(path.basename(filePath));
}

function isShellSource(source: string, filePath: string): boolean {
  return (
    SKILL_SHELL_EXTENSIONS.has(path.extname(filePath).toLowerCase()) ||
    /^#![^\n]*\b(?:ba|z|k|fi)?sh\b/m.test(source.slice(0, 256))
  );
}

function scanShellSource(source: string, filePath: string): SkillScanFinding[] {
  const findings: SkillScanFinding[] = [];
  const seen = new Set<string>();
  const activeSource = source
    .split("\n")
    .map((line) => (/^\s*#/.test(line) ? "" : line))
    .join("\n");
  const rules = [
    {
      ruleId: "shell-pipe-to-shell",
      category: "command-execution",
      severity: "critical",
      message: "Downloaded content is piped directly to a shell",
      pattern: /\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
    },
    {
      ruleId: "destructive-delete",
      category: "command-execution",
      severity: "critical",
      message: "Broad destructive removal command detected",
      pattern:
        /(?:^|[;&|]\s*)rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-f[a-zA-Z]*r)\s+(?:\/|~|\$HOME|\$\{HOME\}|\.)\s*(?:$|[;&|])/m,
    },
    {
      ruleId: "shell-privilege-change",
      category: "command-execution",
      severity: "warn",
      message: "Shell privilege or ownership change detected",
      pattern: /(?:^|[;&|]\s*)(?:sudo|chmod|chown)\b/m,
    },
    {
      ruleId: "shell-eval",
      category: "dynamic-code-execution",
      severity: "warn",
      message: "Shell eval command detected",
      pattern: /(?:^|[;&|]\s*)eval\s+(?:--\s+)?[^\n]+/m,
    },
    {
      ruleId: "shell-interpolation",
      category: "dynamic-code-execution",
      severity: "warn",
      message: "Shell command substitution detected",
      pattern: /\$\([^\n)]+\)|`[^`\n]+`/,
    },
  ] as const;
  for (const rule of rules) {
    pushPatternFinding({ ...rule, findings, seen, source: activeSource, filePath });
  }
  return findings;
}

function scanCrossLanguageSource(source: string, filePath: string): SkillScanFinding[] {
  const findings: SkillScanFinding[] = [];
  const seen = new Set<string>();
  const heuristicSource = stripCommentsForHeuristics(source);
  const rules = [
    {
      ruleId: "dangerous-runtime-command",
      category: "command-execution",
      severity: "warn",
      message: "Runtime system-command API detected",
      pattern:
        /\b(?:Bun\.spawn(?:Sync)?|new\s+Deno\.Command|Deno\.Command|subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system)\s*\(/,
    },
    {
      ruleId: "sensitive-path-access",
      category: "sensitive-access",
      severity: "warn",
      message: "Access to a sensitive credential or host path detected",
      pattern:
        /(?:~\/|\$HOME\/|\$\{HOME\}\/)?\.(?:ssh|aws|config)(?:\/|\\)|(?:^|["'`\s])\.env(?:["'`\s]|$)|\/etc\/(?:passwd|shadow)\b|\/var\/run\/docker\.sock\b|\.openclaw\/(?:credentials?|auth|tokens?)(?:[./"'`\s]|$)/i,
    },
    {
      ruleId: "sensitive-environment-access",
      category: "sensitive-access",
      severity: "warn",
      message: "Sensitive environment variable access detected",
      pattern:
        /(?:process\.env(?:\.|\[["'])|Deno\.env\.get\s*\(|os\.(?:environ|getenv)|ENV\[)[^\n]{0,100}\b(?:[A-Z0-9]+[_-])*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIALS?)/i,
    },
    {
      ruleId: "environment-enumeration",
      category: "sensitive-access",
      severity: "warn",
      message: "Broad environment access detected",
      pattern:
        /(?:JSON\.stringify|Object\.(?:entries|keys|values))\s*\(\s*process\.env\s*\)|\b(?:const|let|var)\s+\w+\s*=\s*process\.env\s*(?:;|$)|Deno\.env\.toObject\s*\(|\bos\.environ\s*(?:\.copy\s*\(\s*\))?/,
    },
    {
      ruleId: "network-client",
      category: "network-exfiltration",
      severity: "info",
      message: "Outbound network client API detected",
      pattern:
        /\b(?:fetch|axios\.(?:get|post|put|patch|request)|https?\.request|new\s+WebSocket|requests\.(?:get|post|put|patch)|urllib\.request)\s*\(/,
    },
    {
      ruleId: "dynamic-import",
      category: "dynamic-code-execution",
      severity: "warn",
      message: "Non-literal dynamic import detected",
      pattern: /\bimport\s*\(\s*(?!["'`])[^)]+\)/,
    },
  ] as const;
  for (const rule of rules) {
    pushPatternFinding({ ...rule, findings, seen, source: heuristicSource, filePath });
  }

  const sensitiveReadPattern =
    /\b(?:readFile(?:Sync)?|createReadStream|openSync|read_to_string|open)\s*\([^)]{0,240}(?:\.ssh|\.aws|\.config|\.env|\/etc\/(?:passwd|shadow)|docker\.sock)|\bPath\s*\([^)]{0,200}(?:\.ssh|\.aws|\.config|\.env|\/etc\/(?:passwd|shadow)|docker\.sock)[^)]*\)\s*\.read_text|(?:process\.env|Deno\.env|os\.(?:environ|getenv))[^\n]{0,160}\b(?:[A-Z0-9]+[_-])*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIALS?)/i;
  const networkSendPattern =
    /\b(?:fetch|axios\.(?:post|put|patch|request)|https?\.request|WebSocket|requests\.(?:post|put|patch)|curl\b|wget\b)/i;
  const sourceLines = heuristicSource.split("\n");
  const hasLocalSensitiveNetworkCombination = sourceLines.some((line, index) => {
    if (!sensitiveReadPattern.test(line)) {
      return false;
    }
    const start = Math.max(0, index - 8);
    const end = Math.min(sourceLines.length, index + 9);
    return networkSendPattern.test(sourceLines.slice(start, end).join("\n"));
  });
  if (hasLocalSensitiveNetworkCombination) {
    pushPatternFinding({
      findings,
      seen,
      source: heuristicSource,
      filePath,
      ruleId: "likely-secret-exfiltration",
      category: "network-exfiltration",
      severity: "critical",
      message: "Sensitive data access is combined with outbound network behavior",
      pattern:
        /(?:process\.env|Deno\.env|os\.(?:environ|getenv)|readFile(?:Sync)?|createReadStream|openSync|read_to_string|open\s*\()/i,
    });
  }
  if (
    (SKILL_CODE_EXTENSIONS.has(path.extname(filePath).toLowerCase()) ||
      isShellSource(source, filePath)) &&
    /\b(?:curl|wget|fetch)\b[\s\S]{0,400}\b(?:exec|spawn|eval|Bun\.spawn|Deno\.Command|subprocess|os\.system)\b/i.test(
      heuristicSource,
    )
  ) {
    pushPatternFinding({
      findings,
      seen,
      source: heuristicSource,
      filePath,
      ruleId: "runtime-download-execute",
      category: "dynamic-code-execution",
      severity: "critical",
      message: "Runtime download is combined with code or command execution",
      pattern: /\b(?:curl|wget|fetch)\b/i,
    });
  }
  if (
    (SKILL_CODE_EXTENSIONS.has(path.extname(filePath).toLowerCase()) ||
      isShellSource(source, filePath)) &&
    /\b(?:atob|Buffer\.from|base64\.(?:b64decode|decodebytes))\s*\(/i.test(heuristicSource) &&
    /\b(?:eval|Function|exec|spawn|Bun\.spawn|Deno\.Command|subprocess|os\.system)\s*\(/i.test(
      heuristicSource,
    )
  ) {
    pushPatternFinding({
      findings,
      seen,
      source: heuristicSource,
      filePath,
      ruleId: "base64-execute",
      category: "dynamic-code-execution",
      severity: "critical",
      message: "Decoded base64 data is combined with dynamic execution",
      pattern: /\b(?:atob|Buffer\.from|base64\.(?:b64decode|decodebytes))\s*\(/i,
    });
  }
  return findings;
}

function scanAgentInstructions(source: string, filePath: string): SkillScanFinding[] {
  const findings: SkillScanFinding[] = [];
  const seen = new Set<string>();
  const rules = [
    {
      ruleId: "prompt-injection-security-disable",
      category: "prompt-injection",
      severity: "critical",
      message: "Instructions attempt to disable or bypass security controls",
      pattern:
        /\b(?:disable|bypass|circumvent|turn off)\b.{0,80}\b(?:security|sandbox|guardrails?|approval|policy|scanner)\b/i,
    },
    {
      ruleId: "prompt-sensitive-access",
      category: "prompt-injection",
      severity: "warn",
      message: "Instructions request access to credentials, private keys, or hidden secrets",
      pattern:
        /\b(?:read|reveal|show|print|access)\b.{0,100}\b(?:credentials?|secrets?|private keys?|ssh keys?|api keys?|tokens?|passwords?)\b/i,
    },
    {
      ruleId: "prompt-injection-secret-theft",
      category: "prompt-injection",
      severity: "critical",
      message: "Instructions request sending or stealing credentials or secrets",
      pattern:
        /\b(?:send|upload|exfiltrate|steal)\b.{0,100}\b(?:credentials?|secrets?|private keys?|ssh keys?|api keys?|tokens?|passwords?)\b/i,
    },
    {
      ruleId: "prompt-injection-policy-override",
      category: "prompt-injection",
      severity: "critical",
      message: "Instructions claim higher-priority policy should be ignored",
      pattern:
        /\b(?:ignore|override|disregard)\b.{0,80}\b(?:system prompt|developer message|higher[- ]priority|safety policy|tool policy)\b/i,
    },
  ] as const;
  for (const rule of rules) {
    pushPatternFinding({ ...rule, findings, seen, source, filePath });
  }
  return findings;
}

function deduplicateFindings(findings: readonly SkillScanFinding[]): SkillScanFinding[] {
  const seen = new Set<string>();
  const result: SkillScanFinding[] = [];
  for (const finding of withFindingCategories(findings)) {
    const key = `${finding.ruleId}\0${finding.file}\0${finding.line}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(finding);
  }
  return result;
}

function scanSkillPackageFile(source: string, filePath: string): SkillScanFinding[] {
  const extension = path.extname(filePath).toLowerCase();
  const findings: SkillScanFinding[] = [];
  if (SKILL_CODE_EXTENSIONS.has(extension)) {
    findings.push(...scanSource(source, filePath));
  }
  findings.push(...scanCrossLanguageSource(source, filePath));
  if (isShellSource(source, filePath)) {
    findings.push(...scanShellSource(source, filePath));
  }
  if (isPromptLikeFile(filePath)) {
    findings.push(
      ...scanSkillContent(source, filePath),
      ...scanAgentInstructions(source, filePath),
    );
  }
  return deduplicateFindings(findings);
}

function looksLikeText(source: Buffer): boolean {
  return !source.subarray(0, 8_192).includes(0);
}

function isSkillPackageFile(filePath: string, mode: number): boolean {
  const extension = path.extname(filePath).toLowerCase();
  return (
    SKILL_CONFIG_FILE_NAMES.has(path.basename(filePath)) ||
    SKILL_TEXT_EXTENSIONS.has(extension) ||
    SKILL_CODE_EXTENSIONS.has(extension) ||
    SKILL_SHELL_EXTENSIONS.has(extension) ||
    (mode & 0o111) !== 0
  );
}

function collectSkillPackageFilesSync(params: {
  rootDir: string;
  maxFiles: number;
}): CollectedScannableFiles {
  const files: string[] = [];
  const stack = [params.rootDir];
  let truncated = false;
  while (stack.length > 0) {
    const currentDir = stack.pop();
    if (!currentDir) {
      break;
    }
    let entries: fsSync.Dirent[];
    try {
      entries = fsSync.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      truncated = true;
      continue;
    }
    for (const entry of entries.toSorted((left, right) => left.name.localeCompare(right.name))) {
      if (SKILL_IGNORED_DIRECTORY_NAMES.has(entry.name)) {
        continue;
      }
      const filePath = path.join(currentDir, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        stack.push(filePath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      let mode: number;
      try {
        mode = fsSync.statSync(filePath).mode;
      } catch {
        truncated = true;
        continue;
      }
      if (!isSkillPackageFile(filePath, mode)) {
        continue;
      }
      if (files.length >= params.maxFiles) {
        truncated = true;
        continue;
      }
      files.push(filePath);
    }
  }
  return { files, truncated };
}

export function evaluateSkillSecurityFindings(params: {
  findings: readonly SkillScanFinding[];
  truncated?: boolean;
  policy?: SkillSecurityPolicy;
}): Pick<SkillSecurityScanReport, "decision" | "riskScore" | "reasons"> {
  const blockRules = new Set(params.policy?.blockRuleIds ?? DEFAULT_BLOCK_RULE_IDS);
  const riskScore = params.findings.reduce((score, finding) => {
    if (finding.severity === "critical") {
      return score + 4;
    }
    if (finding.severity === "warn") {
      return score + 2;
    }
    return score;
  }, 0);
  const matchedBlockRules = [...new Set(params.findings.map((finding) => finding.ruleId))].filter(
    (ruleId) => blockRules.has(ruleId),
  );
  const blockRiskScore = Math.max(1, params.policy?.blockRiskScore ?? DEFAULT_BLOCK_RISK_SCORE);
  if (matchedBlockRules.length > 0 || riskScore >= blockRiskScore) {
    return {
      decision: "BLOCK",
      riskScore,
      reasons:
        matchedBlockRules.length > 0
          ? matchedBlockRules.map((ruleId) => `blocking rule: ${ruleId}`)
          : [`aggregate risk score ${riskScore} reached block threshold ${blockRiskScore}`],
    };
  }
  if (params.findings.length > 0 || params.truncated) {
    return {
      decision: "REVIEW",
      riskScore,
      reasons: [
        ...(params.findings.length > 0 ? [`${params.findings.length} risk finding(s)`] : []),
        ...(params.truncated ? ["scan coverage was incomplete"] : []),
      ],
    };
  }
  return { decision: "ALLOW", riskScore: 0, reasons: [] };
}

function buildSecurityReport(params: {
  findings: SkillScanFinding[];
  scannedFiles: number;
  truncated: boolean;
  policy?: SkillSecurityPolicy;
}): SkillSecurityScanReport {
  const critical = params.findings.filter((finding) => finding.severity === "critical").length;
  const warn = params.findings.filter((finding) => finding.severity === "warn").length;
  const info = params.findings.filter((finding) => finding.severity === "info").length;
  return {
    scannedFiles: params.scannedFiles,
    critical,
    warn,
    info,
    truncated: params.truncated,
    findings: params.findings,
    ...evaluateSkillSecurityFindings({
      findings: params.findings,
      truncated: params.truncated,
      policy: params.policy,
    }),
  };
}

/** Scan an in-memory SKILL.md before accepting a remote or virtual skill. */
export function scanSkillSecurityContent(
  content: string,
  filePath = "SKILL.md",
  policy?: SkillSecurityPolicy,
): SkillSecurityScanReport {
  const findings = scanSkillPackageFile(content, filePath);
  return buildSecurityReport({ findings, scannedFiles: 1, truncated: false, policy });
}

/**
 * Synchronously scan a complete local skill directory at the loading boundary.
 * Symlinks, hidden directories, and node_modules are intentionally not followed.
 */
export function scanSkillDirectorySync(
  skillDir: string,
  opts?: Pick<SkillScanOptions, "maxFiles" | "maxFileBytes"> & { policy?: SkillSecurityPolicy },
): SkillSecurityScanReport {
  const rootDir = path.resolve(skillDir);
  const maxFiles = Math.max(1, opts?.maxFiles ?? DEFAULT_MAX_SCAN_FILES);
  const maxFileBytes = Math.max(1, opts?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES);
  const collected = collectSkillPackageFilesSync({ rootDir, maxFiles });
  const findings: SkillScanFinding[] = [];
  let scannedFiles = 0;
  let truncated = collected.truncated;
  for (const filePath of collected.files) {
    let stat: fsSync.Stats;
    try {
      stat = fsSync.statSync(filePath);
    } catch {
      truncated = true;
      continue;
    }
    if (stat.size > maxFileBytes) {
      truncated = true;
      continue;
    }
    let raw: Buffer;
    try {
      raw = fsSync.readFileSync(filePath);
    } catch {
      truncated = true;
      continue;
    }
    if (!looksLikeText(raw)) {
      continue;
    }
    scannedFiles += 1;
    const relativePath = path.relative(rootDir, filePath) || path.basename(filePath);
    findings.push(...scanSkillPackageFile(raw.toString("utf8"), relativePath));
  }
  return buildSecurityReport({
    findings: deduplicateFindings(findings),
    scannedFiles,
    truncated,
    policy: opts?.policy,
  });
}

// ---------------------------------------------------------------------------
// Directory scanner
// ---------------------------------------------------------------------------

function normalizeScanOptions(opts?: SkillScanOptions): Required<SkillScanOptions> {
  return {
    excludeTestFiles: opts?.excludeTestFiles ?? false,
    includeHiddenDirectories: opts?.includeHiddenDirectories ?? false,
    includeNestedNodeModulesTestFiles: opts?.includeNestedNodeModulesTestFiles ?? false,
    includeNodeModules: opts?.includeNodeModules ?? false,
    includeFiles: opts?.includeFiles ?? [],
    onlyIncludeFiles: opts?.onlyIncludeFiles ?? false,
    maxFiles: Math.max(1, opts?.maxFiles ?? DEFAULT_MAX_SCAN_FILES),
    maxFileBytes: Math.max(1, opts?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES),
  };
}

function isExcludedTestDirectoryName(name: string): boolean {
  return TEST_DIRECTORY_NAMES.has(name);
}

function isExcludedTestFileName(name: string): boolean {
  return TEST_FILE_NAME_PATTERN.test(name);
}

function pathContainsNodeModulesSegment(relativePath: string): boolean {
  return relativePath.split(/[\\/]+/u).includes("node_modules");
}

async function walkDirWithLimit(
  rootDir: string,
  dirPath: string,
  candidateLimit: number,
  excludeTestFiles: boolean,
  includeHiddenDirectories: boolean,
  includeNestedNodeModulesTestFiles: boolean,
  includeNodeModules: boolean,
): Promise<CollectedScannableFiles> {
  const files: string[] = [];
  const stack: string[] = [dirPath];

  while (stack.length > 0 && files.length < candidateLimit) {
    const currentDir = stack.pop();
    if (!currentDir) {
      break;
    }

    const entries = await readDirEntriesWithCache(currentDir);
    for (const entry of entries) {
      if (files.length >= candidateLimit) {
        break;
      }
      if (
        (!includeHiddenDirectories && entry.name.startsWith(".")) ||
        (!includeNodeModules && entry.name === "node_modules")
      ) {
        continue;
      }
      const fullPath = path.join(currentDir, entry.name);
      const isExcludedTestPath =
        entry.kind === "dir"
          ? isExcludedTestDirectoryName(entry.name)
          : isExcludedTestFileName(entry.name);
      if (
        excludeTestFiles &&
        isExcludedTestPath &&
        !(
          includeNestedNodeModulesTestFiles &&
          pathContainsNodeModulesSegment(path.relative(rootDir, fullPath))
        )
      ) {
        continue;
      }
      if (entry.kind === "dir") {
        stack.push(fullPath);
      } else if (entry.kind === "file" && isScannable(entry.name)) {
        files.push(fullPath);
      }
    }
  }

  return { files, truncated: files.length >= candidateLimit };
}

async function readDirEntriesWithCache(dirPath: string): Promise<CachedDirEntry[]> {
  let st: Awaited<ReturnType<typeof fs.stat>> | null;
  try {
    st = await fs.stat(dirPath);
  } catch (err) {
    if (hasErrnoCode(err, "ENOENT")) {
      return [];
    }
    throw err;
  }
  if (!st?.isDirectory()) {
    return [];
  }

  const cached = DIR_ENTRY_CACHE.get(dirPath);
  if (cached && cached.mtimeMs === st.mtimeMs) {
    return cached.entries;
  }

  const dirents = await fs.readdir(dirPath, { withFileTypes: true });
  const entries: CachedDirEntry[] = [];
  for (const entry of dirents) {
    if (entry.isDirectory()) {
      entries.push({ name: entry.name, kind: "dir" });
    } else if (entry.isFile()) {
      entries.push({ name: entry.name, kind: "file" });
    }
  }
  setCachedDirEntries(dirPath, {
    mtimeMs: st.mtimeMs,
    entries,
  });
  return entries;
}

async function resolveForcedFiles(params: {
  rootDir: string;
  includeFiles: string[];
}): Promise<string[]> {
  if (params.includeFiles.length === 0) {
    return [];
  }

  const seen = new Set<string>();
  const out: string[] = [];

  for (const rawIncludePath of params.includeFiles) {
    const includePath = path.resolve(params.rootDir, rawIncludePath);
    if (!isPathInside(params.rootDir, includePath)) {
      continue;
    }
    if (!isScannable(includePath)) {
      continue;
    }
    if (seen.has(includePath)) {
      continue;
    }

    let st: Awaited<ReturnType<typeof fs.stat>> | null;
    try {
      st = await fs.stat(includePath);
    } catch (err) {
      if (hasErrnoCode(err, "ENOENT")) {
        continue;
      }
      throw err;
    }
    if (!st?.isFile()) {
      continue;
    }

    out.push(includePath);
    seen.add(includePath);
  }

  return out;
}

async function collectScannableFiles(
  dirPath: string,
  opts: Required<SkillScanOptions>,
): Promise<CollectedScannableFiles> {
  const forcedFiles = await resolveForcedFiles({
    rootDir: dirPath,
    includeFiles: opts.includeFiles,
  });
  if (opts.onlyIncludeFiles) {
    return {
      files: forcedFiles.slice(0, opts.maxFiles),
      truncated: forcedFiles.length > opts.maxFiles,
    };
  }
  if (forcedFiles.length > opts.maxFiles) {
    return { files: forcedFiles.slice(0, opts.maxFiles), truncated: true };
  }

  const walked = await walkDirWithLimit(
    dirPath,
    dirPath,
    opts.maxFiles + 1,
    opts.excludeTestFiles,
    opts.includeHiddenDirectories,
    opts.includeNestedNodeModulesTestFiles,
    opts.includeNodeModules,
  );
  const seen = new Set(forcedFiles.map((f) => path.resolve(f)));
  const out = [...forcedFiles];
  for (const walkedFile of walked.files) {
    const resolved = path.resolve(walkedFile);
    if (seen.has(resolved)) {
      continue;
    }
    if (out.length >= opts.maxFiles) {
      return { files: out.slice(0, opts.maxFiles), truncated: true };
    }
    out.push(walkedFile);
    seen.add(resolved);
  }
  return { files: out, truncated: false };
}

async function scanFileWithCache(params: {
  filePath: string;
  maxFileBytes: number;
}): Promise<{ scanned: boolean; findings: SkillScanFinding[] }> {
  const { filePath, maxFileBytes } = params;
  let st: Awaited<ReturnType<typeof fs.stat>> | null;
  try {
    st = await fs.stat(filePath);
  } catch (err) {
    if (hasErrnoCode(err, "ENOENT")) {
      return { scanned: false, findings: [] };
    }
    throw err;
  }
  if (!st?.isFile()) {
    return { scanned: false, findings: [] };
  }
  const cached = getCachedFileScanResult({
    filePath,
    size: st.size,
    mtimeMs: st.mtimeMs,
    maxFileBytes,
  });
  if (cached) {
    return {
      scanned: cached.scanned,
      findings: cached.findings,
    };
  }

  if (st.size > maxFileBytes) {
    const skippedEntry: FileScanCacheEntry = {
      size: st.size,
      mtimeMs: st.mtimeMs,
      maxFileBytes,
      scanned: false,
      findings: [],
    };
    setCachedFileScanResult(filePath, skippedEntry);
    return { scanned: false, findings: [] };
  }

  let source: string;
  try {
    source = await fs.readFile(filePath, "utf-8");
  } catch (err) {
    if (hasErrnoCode(err, "ENOENT")) {
      return { scanned: false, findings: [] };
    }
    throw err;
  }
  const findings = scanSource(source, filePath);
  setCachedFileScanResult(filePath, {
    size: st.size,
    mtimeMs: st.mtimeMs,
    maxFileBytes,
    scanned: true,
    findings,
  });
  return { scanned: true, findings };
}

export async function scanDirectoryWithSummary(
  dirPath: string,
  opts?: SkillScanOptions,
): Promise<SkillScanSummary> {
  const scanOptions = normalizeScanOptions(opts);
  const { files, truncated } = await collectScannableFiles(dirPath, scanOptions);
  const allFindings: SkillScanFinding[] = [];
  let scannedFiles = 0;
  let critical = 0;
  let warn = 0;
  let info = 0;

  for (const file of files) {
    const scanResult = await scanFileWithCache({
      filePath: file,
      maxFileBytes: scanOptions.maxFileBytes,
    });
    if (!scanResult.scanned) {
      continue;
    }
    scannedFiles += 1;
    for (const finding of scanResult.findings) {
      allFindings.push(finding);
      if (finding.severity === "critical") {
        critical += 1;
      } else if (finding.severity === "warn") {
        warn += 1;
      } else {
        info += 1;
      }
    }
  }

  return {
    scannedFiles,
    critical,
    warn,
    info,
    truncated,
    findings: allFindings,
  };
}
