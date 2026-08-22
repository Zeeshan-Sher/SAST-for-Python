/**
 * Python Vulnerability Scanner Engine
 * Detects common security vulnerabilities in Python code through static analysis
 */

import type { InsertVulnerability } from "../drizzle/schema";

export type VulnerabilityType =
  | "SQL Injection"
  | "Command Injection"
  | "Hardcoded Password"
  | "Hardcoded API Key"
  | "Dangerous Function"
  | "XSS Pattern";

export type SeverityLevel = "Critical" | "High" | "Medium" | "Low";

export interface DetectedVulnerability {
  type: VulnerabilityType;
  severity: SeverityLevel;
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  description: string;
  recommendation: string;
}

export interface ScanResult {
  vulnerabilities: DetectedVulnerability[];
  securityScore: number;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  vulnerabilityCount: number;
}

/**
 * Splits code into lines and tracks line/column positions
 */
function getCodeLines(code: string): string[] {
  return code.split("\n");
}

/**
 * Extracts a code snippet around a given line
 */
function getCodeSnippet(lines: string[], lineNumber: number, context = 1): string {
  const start = Math.max(0, lineNumber - context - 1);
  const end = Math.min(lines.length, lineNumber + context);
  return lines.slice(start, end).join("\n");
}

/**
 * SQL Injection Detection
 * Looks for string concatenation with user input in SQL queries
 */
function detectSQLInjection(code: string, lines: string[]): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = [];
  const patterns = [
    /["'].*SELECT.*["']\s*\+/gi,
    /["'].*INSERT.*["']\s*\+/gi,
    /["'].*UPDATE.*["']\s*\+/gi,
    /["'].*DELETE.*["']\s*\+/gi,
    /f["'`].*SELECT.*\{/gi,
    /f["'`].*INSERT.*\{/gi,
    /f["'`].*UPDATE.*\{/gi,
    /f["'`].*DELETE.*\{/gi,
  ];

  lines.forEach((line, index) => {
    patterns.forEach((pattern) => {
      if (pattern.test(line)) {
        vulnerabilities.push({
          type: "SQL Injection",
          severity: "Critical",
          lineNumber: index + 1,
          columnNumber: 0,
          codeSnippet: getCodeSnippet(lines, index + 1),
          description:
            "Potential SQL injection vulnerability detected. User input is being concatenated directly into SQL queries without proper parameterization.",
          recommendation:
            "Use parameterized queries or prepared statements. Replace string concatenation with query parameters: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        });
      }
    });
  });

  return vulnerabilities;
}

/**
 * Command Injection Detection
 * Looks for shell command execution with user input
 */
function detectCommandInjection(code: string, lines: string[]): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = [];
  const patterns = [
    /os\.system\s*\(/gi,
    /subprocess\s*\.\s*call\s*\(/gi,
    /subprocess\s*\.\s*Popen\s*\(/gi,
    /shell\s*=\s*True/gi,
  ];

  lines.forEach((line, index) => {
    patterns.forEach((pattern) => {
      if (pattern.test(line)) {
        vulnerabilities.push({
          type: "Command Injection",
          severity: "Critical",
          lineNumber: index + 1,
          columnNumber: 0,
          codeSnippet: getCodeSnippet(lines, index + 1),
          description:
            "Potential command injection vulnerability. User input is being passed to shell commands without proper sanitization.",
          recommendation:
            "Avoid using shell=True. Use subprocess with a list of arguments: subprocess.run(['command', arg1, arg2]) instead of subprocess.run(f'command {arg1} {arg2}', shell=True)",
        });
      }
    });
  });

  return vulnerabilities;
}

/**
 * Hardcoded Password Detection
 * Looks for common password variable names with hardcoded values
 */
function detectHardcodedPasswords(code: string, lines: string[]): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = [];
  const patterns = [
    /password\s*=\s*["'`][^"'`]{1,}["'`]/gi,
    /passwd\s*=\s*["'`][^"'`]{1,}["'`]/gi,
    /pwd\s*=\s*["'`][^"'`]{1,}["'`]/gi,
    /secret\s*=\s*["'`][^"'`]{1,}["'`]/gi,
    /token\s*=\s*["'`][^"'`]{1,}["'`]/gi,
  ];

  lines.forEach((line, index) => {
    patterns.forEach((pattern) => {
      if (pattern.test(line) && !line.trim().startsWith("#")) {
        vulnerabilities.push({
          type: "Hardcoded Password",
          severity: "Critical",
          lineNumber: index + 1,
          columnNumber: 0,
          codeSnippet: getCodeSnippet(lines, index + 1),
          description:
            "Hardcoded password or secret detected in source code. This is a critical security risk.",
          recommendation:
            "Move secrets to environment variables or a secure secrets management system. Use: password = os.getenv('DB_PASSWORD')",
        });
      }
    });
  });

  return vulnerabilities;
}

/**
 * Hardcoded API Key Detection
 * Looks for common API key patterns
 */
function detectHardcodedAPIKeys(code: string, lines: string[]): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = [];
  const patterns = [
    /api_key\s*=\s*["'`][a-zA-Z0-9_\-]{20,}["'`]/gi,
    /apikey\s*=\s*["'`][a-zA-Z0-9_\-]{20,}["'`]/gi,
    /api_secret\s*=\s*["'`][a-zA-Z0-9_\-]{20,}["'`]/gi,
    /access_token\s*=\s*["'`][a-zA-Z0-9_\-]{20,}["'`]/gi,
    /bearer\s*["'`][a-zA-Z0-9_\-]{20,}["'`]/gi,
  ];

  lines.forEach((line, index) => {
    patterns.forEach((pattern) => {
      if (pattern.test(line) && !line.trim().startsWith("#")) {
        vulnerabilities.push({
          type: "Hardcoded API Key",
          severity: "Critical",
          lineNumber: index + 1,
          columnNumber: 0,
          codeSnippet: getCodeSnippet(lines, index + 1),
          description:
            "Hardcoded API key detected in source code. This exposes sensitive credentials to anyone with access to the repository.",
          recommendation:
            "Store API keys in environment variables or a secrets vault. Use: api_key = os.getenv('API_KEY')",
        });
      }
    });
  });

  return vulnerabilities;
}

/**
 * Dangerous Functions Detection
 * Looks for eval, exec, os.system, and subprocess.run with shell=True
 * Exactly as specified: only subprocess.run with shell=True, not all subprocess.run calls
 */
function detectDangerousFunctions(code: string, lines: string[]): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = [];

  lines.forEach((line, index) => {
    // Detect eval()
    if (/\beval\s*\(/gi.test(line)) {
      vulnerabilities.push({
        type: "Dangerous Function",
        severity: "High",
        lineNumber: index + 1,
        columnNumber: 0,
        codeSnippet: getCodeSnippet(lines, index + 1),
        description: "Use of dangerous function eval(). This can execute arbitrary code and poses a significant security risk.",
        recommendation:
          "Avoid using eval(). Use safer alternatives like ast.literal_eval() for parsing data structures.",
      });
    }

    // Detect exec()
    if (/\bexec\s*\(/gi.test(line)) {
      vulnerabilities.push({
        type: "Dangerous Function",
        severity: "High",
        lineNumber: index + 1,
        columnNumber: 0,
        codeSnippet: getCodeSnippet(lines, index + 1),
        description: "Use of dangerous function exec(). This can execute arbitrary code and poses a significant security risk.",
        recommendation:
          "Avoid using exec(). Use safer alternatives like ast.literal_eval() for parsing data structures.",
      });
    }

    // Detect os.system()
    if (/os\.system\s*\(/gi.test(line)) {
      vulnerabilities.push({
        type: "Dangerous Function",
        severity: "High",
        lineNumber: index + 1,
        columnNumber: 0,
        codeSnippet: getCodeSnippet(lines, index + 1),
        description: "Use of dangerous function os.system(). This executes shell commands and poses a command injection risk.",
        recommendation:
          "Avoid using os.system(). Use subprocess.run() with a list of arguments instead for safer command execution.",
      });
    }

    // Detect subprocess.run(..., shell=True) - only flag if shell=True is present on same line
    if (/subprocess\.run\s*\(/gi.test(line) && /shell\s*=\s*True/gi.test(line)) {
      vulnerabilities.push({
        type: "Dangerous Function",
        severity: "High",
        lineNumber: index + 1,
        columnNumber: 0,
        codeSnippet: getCodeSnippet(lines, index + 1),
        description: "Use of subprocess.run() with shell=True. This poses a command injection risk.",
        recommendation:
          "Avoid using shell=True. Pass arguments as a list to subprocess.run() for safer command execution.",
      });
    }
  });

  return vulnerabilities;
}

/**
 * Basic XSS Pattern Detection
 * Looks for patterns that could lead to XSS vulnerabilities in web frameworks
 */
function detectXSSPatterns(code: string, lines: string[]): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = [];
  const patterns = [
    /render_template_string\s*\(/gi,
    /Markup\s*\(/gi,
    /f["'`].*<.*>.*\{.*\}/gi,
    /html\s*=\s*f["'`].*<.*>/gi,
    /\.format\s*\([^)]*\).*html/gi,
  ];

  lines.forEach((line, index) => {
    patterns.forEach((pattern) => {
      if (pattern.test(line)) {
        vulnerabilities.push({
          type: "XSS Pattern",
          severity: "High",
          lineNumber: index + 1,
          columnNumber: 0,
          codeSnippet: getCodeSnippet(lines, index + 1),
          description:
            "Potential XSS (Cross-Site Scripting) vulnerability. User input may be rendered as HTML without proper escaping.",
          recommendation:
            "Always escape user input before rendering in HTML. Use template auto-escaping: Markup(escape(user_input)) or use Jinja2 with autoescape enabled.",
        });
      }
    });
  });

  return vulnerabilities;
}

/**
 * Calculates security score based on vulnerabilities found
 * Score starts at 100 and decreases based on severity and count
 */
function calculateSecurityScore(vulnerabilities: DetectedVulnerability[]): number {
  let score = 100;

  vulnerabilities.forEach((vuln) => {
    switch (vuln.severity) {
      case "Critical":
        score -= 20;
        break;
      case "High":
        score -= 10;
        break;
      case "Medium":
        score -= 5;
        break;
      case "Low":
        score -= 2;
        break;
    }
  });

  return Math.max(0, score);
}

/**
 * Determines overall risk level based on vulnerabilities
 */
function determineRiskLevel(vulnerabilities: DetectedVulnerability[]): "Critical" | "High" | "Medium" | "Low" {
  const hasCritical = vulnerabilities.some((v) => v.severity === "Critical");
  const hasHigh = vulnerabilities.some((v) => v.severity === "High");
  const hasMedium = vulnerabilities.some((v) => v.severity === "Medium");

  if (hasCritical) return "Critical";
  if (hasHigh) return "High";
  if (hasMedium) return "Medium";
  return "Low";
}

/**
 * Main scanning function
 * Runs all detection rules and returns comprehensive scan results
 */
export function scanPythonCode(code: string): ScanResult {
  const lines = getCodeLines(code);

  // Run all detection rules
  const sqlInjections = detectSQLInjection(code, lines);
  const commandInjections = detectCommandInjection(code, lines);
  const hardcodedPasswords = detectHardcodedPasswords(code, lines);
  const hardcodedAPIKeys = detectHardcodedAPIKeys(code, lines);
  const dangerousFunctions = detectDangerousFunctions(code, lines);
  const xssPatterns = detectXSSPatterns(code, lines);

  // Combine all vulnerabilities
  const allVulnerabilities = [
    ...sqlInjections,
    ...commandInjections,
    ...hardcodedPasswords,
    ...hardcodedAPIKeys,
    ...dangerousFunctions,
    ...xssPatterns,
  ];

  // Remove duplicates based on line number and type
  const uniqueVulnerabilities = Array.from(
    new Map(
      allVulnerabilities.map((v) => [`${v.lineNumber}-${v.type}`, v])
    ).values()
  );

  const securityScore = calculateSecurityScore(uniqueVulnerabilities);
  const riskLevel = determineRiskLevel(uniqueVulnerabilities);

  return {
    vulnerabilities: uniqueVulnerabilities,
    securityScore,
    riskLevel,
    vulnerabilityCount: uniqueVulnerabilities.length,
  };
}
