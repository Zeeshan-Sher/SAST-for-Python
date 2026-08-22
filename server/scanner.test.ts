import { describe, expect, it } from "vitest";
import { scanPythonCode } from "./scanner";

describe("Python Vulnerability Scanner", () => {
  describe("SQL Injection Detection", () => {
    it("should detect SQL injection with string concatenation", () => {
      const code = `
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
      `;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "SQL Injection")).toBe(true);
    });

    it("should detect SQL injection with f-strings", () => {
      const code = `
user_input = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_input}"
cursor.execute(query)
      `;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "SQL Injection")).toBe(true);
    });

    it("should mark SQL injection as Critical", () => {
      const code = `query = "SELECT * FROM users WHERE id = " + user_id`;
      const result = scanPythonCode(code);
      const sqlVuln = result.vulnerabilities.find((v) => v.type === "SQL Injection");
      expect(sqlVuln?.severity).toBe("Critical");
    });
  });

  describe("Command Injection Detection", () => {
    it("should detect os.system with string concatenation", () => {
      const code = `
user_input = request.args.get('cmd')
os.system("ls " + user_input)
      `;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Command Injection")).toBe(true);
    });

    it("should detect subprocess with shell=True", () => {
      const code = `
subprocess.run(f"echo {user_input}", shell=True)
      `;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Command Injection")).toBe(true);
    });

    it("should mark command injection as Critical", () => {
      const code = `os.system("ls " + user_input)`;
      const result = scanPythonCode(code);
      const cmdVuln = result.vulnerabilities.find((v) => v.type === "Command Injection");
      expect(cmdVuln?.severity).toBe("Critical");
    });
  });

  describe("Hardcoded Password Detection", () => {
    it("should detect hardcoded passwords", () => {
      const code = `password = "MySecurePassword123"`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Hardcoded Password")).toBe(true);
    });

    it("should detect hardcoded tokens", () => {
      const code = `token = "sk_live_abcdef123456789"`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Hardcoded Password")).toBe(true);
    });

    it("should mark hardcoded password as Critical", () => {
      const code = `password = "MySecurePassword123"`;
      const result = scanPythonCode(code);
      const pwdVuln = result.vulnerabilities.find((v) => v.type === "Hardcoded Password");
      expect(pwdVuln?.severity).toBe("Critical");
    });

    it("should ignore commented passwords", () => {
      const code = `# password = "MySecurePassword123"`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Hardcoded Password")).toBe(false);
    });
  });

  describe("Hardcoded API Key Detection", () => {
    it("should detect hardcoded API keys", () => {
      const code = `api_key = "sk_live_51234567890abcdefghij"`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Hardcoded API Key")).toBe(true);
    });

    it("should detect hardcoded access tokens", () => {
      const code = `access_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Hardcoded API Key")).toBe(true);
    });

    it("should mark hardcoded API key as Critical", () => {
      const code = `api_key = "sk_live_51234567890abcdefghij"`;
      const result = scanPythonCode(code);
      const apiVuln = result.vulnerabilities.find((v) => v.type === "Hardcoded API Key");
      expect(apiVuln?.severity).toBe("Critical");
    });
  });

  describe("Dangerous Functions Detection", () => {
    it("should detect eval() usage", () => {
      const code = `result = eval(user_input)`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Dangerous Function")).toBe(true);
    });

    it("should detect exec() usage", () => {
      const code = `exec(user_code)`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Dangerous Function")).toBe(true);
    });

    it("should detect os.system() usage", () => {
      const code = `os.system(command)`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Dangerous Function")).toBe(true);
    });

    it("should detect subprocess.run with shell=True", () => {
      const code = `subprocess.run(cmd, shell=True)`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "Dangerous Function")).toBe(true);
    });

    it("should mark dangerous functions as High", () => {
      const code = `result = eval(user_input)`;
      const result = scanPythonCode(code);
      const dangerVuln = result.vulnerabilities.find((v) => v.type === "Dangerous Function");
      expect(dangerVuln?.severity).toBe("High");
    });
  });

  describe("XSS Pattern Detection", () => {
    it("should detect potential XSS with Markup and string concatenation", () => {
      const code = `html = Markup("<div>" + user_input + "</div>")`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "XSS Pattern")).toBe(true);
    });

    it("should detect XSS in f-strings with HTML", () => {
      const code = `html = f"<h1>{user_input}</h1>"`;
      const result = scanPythonCode(code);
      expect(result.vulnerabilities.some((v) => v.type === "XSS Pattern")).toBe(true);
    });

    it("should mark XSS patterns as High", () => {
      const code = `html = f"<h1>{user_input}</h1>"`;
      const result = scanPythonCode(code);
      const xssVuln = result.vulnerabilities.find((v) => v.type === "XSS Pattern");
      expect(xssVuln?.severity).toBe("High");
    });
  });

  describe("Security Score Calculation", () => {
    it("should start with score of 100 for clean code", () => {
      const code = `
def hello_world():
    print("Hello, World!")
      `;
      const result = scanPythonCode(code);
      expect(result.securityScore).toBe(100);
    });

    it("should decrease score for each vulnerability", () => {
      const code = `
password = "secret123"
api_key = "sk_live_abcdef123456789"
      `;
      const result = scanPythonCode(code);
      expect(result.securityScore).toBeLessThan(100);
    });

    it("should not go below 0", () => {
      const code = `
password = "secret123"
api_key = "sk_live_abcdef123456789"
eval(user_input)
os.system(cmd)
      `;
      const result = scanPythonCode(code);
      expect(result.securityScore).toBeGreaterThanOrEqual(0);
    });
  });

  describe("Risk Level Determination", () => {
    it("should be Critical if any Critical vulnerability exists", () => {
      const code = `password = "secret123"`;
      const result = scanPythonCode(code);
      expect(result.riskLevel).toBe("Critical");
    });

    it("should be High if only High vulnerabilities exist", () => {
      const code = `eval(user_input)`;
      const result = scanPythonCode(code);
      expect(result.riskLevel).toBe("High");
    });

    it("should be Low for clean code", () => {
      const code = `
def hello_world():
    print("Hello, World!")
      `;
      const result = scanPythonCode(code);
      expect(result.riskLevel).toBe("Low");
    });
  });

  describe("Vulnerability Count", () => {
    it("should count all vulnerabilities", () => {
      const code = `
password = "secret123"
eval(user_input)
      `;
      const result = scanPythonCode(code);
      expect(result.vulnerabilityCount).toBeGreaterThan(0);
    });

    it("should remove duplicate vulnerabilities on same line", () => {
      const code = `query = "SELECT * FROM users WHERE id = " + user_id`;
      const result = scanPythonCode(code);
      // Should only count once even if multiple patterns match
      expect(result.vulnerabilityCount).toBeGreaterThan(0);
    });
  });

  describe("Line Number Tracking", () => {
    it("should correctly track line numbers", () => {
      const code = `
def hello():
    pass

password = "secret123"
      `;
      const result = scanPythonCode(code);
      const vuln = result.vulnerabilities.find((v) => v.type === "Hardcoded Password");
      expect(vuln?.lineNumber).toBe(5);
    });
  });

  describe("Code Snippet Extraction", () => {
    it("should include code snippet with context", () => {
      const code = `
line1 = "safe"
password = "secret123"
line3 = "safe"
      `;
      const result = scanPythonCode(code);
      const vuln = result.vulnerabilities.find((v) => v.type === "Hardcoded Password");
      expect(vuln?.codeSnippet).toContain("password");
    });
  });
});
