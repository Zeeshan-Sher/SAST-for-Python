import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import { z } from "zod";
import { scanPythonCode } from "./scanner";
import { invokeLLM } from "./_core/llm";

// In-memory storage for scans (replace with database in production)
const scansStore = new Map();
const vulnerabilitiesStore = new Map();
let scanIdCounter = 1;

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => {
      if (opts.ctx.user) return opts.ctx.user;
      // Default user for standalone mode
      return {
        id: 1,
        openId: "standalone-user",
        name: "Security Engineer",
        email: "security@local.test",
        loginMethod: "standalone",
        role: "admin" as const,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastSignedIn: new Date(),
      };
    }),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  /**
   * Code scanning procedures
   */
  scan: router({
    /**
     * Analyze Python code for vulnerabilities
     */
    analyze: publicProcedure
      .input(
        z.object({
          fileName: z.string().min(1),
          sourceCode: z.string().min(1),
        })
      )
      .mutation(async ({ ctx, input }) => {
        // Run static analysis
        const scanResult = scanPythonCode(input.sourceCode);

        // Store scan in memory
        const scanId = scanIdCounter++;
        const codeScan = {
          id: scanId,
          userId: ctx.user?.id || 1,
          fileName: input.fileName,
          sourceCode: input.sourceCode,
          securityScore: scanResult.securityScore,
          riskLevel: scanResult.riskLevel,
          vulnerabilityCount: scanResult.vulnerabilityCount,
          createdAt: new Date(),
        };

        scansStore.set(scanId, codeScan);

        // Store vulnerabilities
        const vulnRecords = scanResult.vulnerabilities.map((v) => ({
          id: Math.random(),
          scanId: scanId,
          type: v.type,
          severity: v.severity,
          lineNumber: v.lineNumber,
          columnNumber: v.columnNumber,
          codeSnippet: v.codeSnippet,
          description: v.description,
          recommendation: v.recommendation,
        }));

        vulnerabilitiesStore.set(scanId, vulnRecords);

        return {
          scanId: codeScan.id,
          fileName: codeScan.fileName,
          securityScore: codeScan.securityScore,
          riskLevel: codeScan.riskLevel,
          vulnerabilityCount: codeScan.vulnerabilityCount,
          vulnerabilities: scanResult.vulnerabilities,
        };
      }),

    /**
     * Get scan results with vulnerabilities
     */
    getResults: publicProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = scansStore.get(input.scanId);

        if (!scan) {
          throw new Error("Scan not found");
        }

        const vulns = vulnerabilitiesStore.get(input.scanId) || [];

        return {
          scan,
          vulnerabilities: vulns,
        };
      }),

    /**
     * Get user's scan history
     */
    history: publicProcedure.query(async ({ ctx }) => {
      const userScans = Array.from(scansStore.values()).filter(
        scan => scan.userId === (ctx.user?.id || 1)
      );
      return userScans;
    }),

    /**
     * Generate AI explanation for a vulnerability
     */
    explainVulnerability: publicProcedure
      .input(
        z.object({
          type: z.string(),
          codeSnippet: z.string(),
          description: z.string(),
        })
      )
      .mutation(async ({ input }) => {
        try {
          const response = await invokeLLM({
            model: "gemini-3.5-flash",
            messages: [
              {
                role: "system",
                content:
                  "You are a security expert explaining Python code vulnerabilities to developers. Provide clear, concise explanations of the security risk and why it matters.",
              },
              {
                role: "user",
                content: `Explain this ${input.type} vulnerability in Python code:\n\nCode:\n${input.codeSnippet}\n\nInitial description: ${input.description}\n\nProvide a detailed explanation of the vulnerability, the security risk, and why this pattern is dangerous.`,
              },
            ],
          });

          const content = response.choices[0]?.message.content;
          return {
            explanation:
              typeof content === "string"
                ? content
                : "Unable to generate explanation",
          };
        } catch (error: any) {
          console.error("Failed to generate explanation:", error);
          return {
            explanation:
              `AI Error: ${error?.message || "Unknown error"}. Check your .env credentials.`,
          };
        }
      }),

    /**
     * Generate remediation recommendations for a vulnerability
     */
    generateRecommendations: publicProcedure
      .input(
        z.object({
          type: z.string(),
          codeSnippet: z.string(),
          recommendation: z.string(),
        })
      )
      .mutation(async ({ input }) => {
        try {
          const response = await invokeLLM({
            model: "gemini-3.5-flash",
            messages: [
              {
                role: "system",
                content:
                  "You are a Python security expert. Provide practical, code-focused remediation advice for security vulnerabilities. Include specific Python code examples.",
              },
              {
                role: "user",
                content: `Provide detailed remediation steps for this ${input.type} vulnerability:\n\nVulnerable code:\n${input.codeSnippet}\n\nInitial recommendation: ${input.recommendation}\n\nProvide step-by-step remediation advice with specific Python code examples showing the secure approach.`,
              },
            ],
          });

          const content = response.choices[0]?.message.content;
          return {
            recommendations:
              typeof content === "string"
                ? content
                : "Unable to generate recommendations",
          };
        } catch (error: any) {
          console.error("Failed to generate recommendations:", error);
          return {
            recommendations:
              `AI Error: ${error?.message || "Unknown error"}. Check your .env credentials.`,
          };
        }
      }),
  }),
});

export type AppRouter = typeof appRouter;
