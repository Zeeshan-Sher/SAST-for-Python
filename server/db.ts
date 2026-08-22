import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { InsertUser, users, codeScans, vulnerabilities, type CodeScan, type Vulnerability } from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

/**
 * Create a new code scan record
 */
export async function createCodeScan(scan: {
  userId: number;
  fileName: string;
  sourceCode: string;
  securityScore: number;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  vulnerabilityCount: number;
}): Promise<CodeScan> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot create code scan: database not available, returning mock scan");
    return {
      id: Math.floor(Math.random() * 10000) + 1,
      userId: scan.userId,
      fileName: scan.fileName,
      sourceCode: scan.sourceCode,
      securityScore: scan.securityScore,
      riskLevel: scan.riskLevel,
      vulnerabilityCount: scan.vulnerabilityCount,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  try {
    const result = await db.insert(codeScans).values(scan);
    const scanId = result[0]?.insertId;
    if (!scanId) {
      return {
        id: Math.floor(Math.random() * 10000) + 1,
        userId: scan.userId,
        fileName: scan.fileName,
        sourceCode: scan.sourceCode,
        securityScore: scan.securityScore,
        riskLevel: scan.riskLevel,
        vulnerabilityCount: scan.vulnerabilityCount,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
    }

    const created = await db.select().from(codeScans).where(eq(codeScans.id, scanId as number)).limit(1);
    return created.length > 0 ? created[0] : {
      id: scanId as number,
      userId: scan.userId,
      fileName: scan.fileName,
      sourceCode: scan.sourceCode,
      securityScore: scan.securityScore,
      riskLevel: scan.riskLevel,
      vulnerabilityCount: scan.vulnerabilityCount,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  } catch (error) {
    console.warn("[Database] Failed to create code scan, returning memory fallback:", error);
    // Return mock code scan object for local testing without DB
    return {
      id: Math.floor(Math.random() * 10000) + 1,
      userId: scan.userId,
      fileName: scan.fileName,
      sourceCode: scan.sourceCode,
      securityScore: scan.securityScore,
      riskLevel: scan.riskLevel,
      vulnerabilityCount: scan.vulnerabilityCount,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }
}

/**
 * Get code scan by ID
 */
export async function getCodeScanById(scanId: number): Promise<CodeScan | null> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get code scan: database not available");
    return null;
  }

  const result = await db.select().from(codeScans).where(eq(codeScans.id, scanId)).limit(1);
  return result.length > 0 ? result[0] : null;
}

/**
 * Get all code scans for a user
 */
export async function getUserCodeScans(userId: number): Promise<CodeScan[]> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user code scans: database not available");
    return [];
  }

  return await db.select().from(codeScans).where(eq(codeScans.userId, userId));
}

/**
 * Create vulnerability records
 */
export async function createVulnerabilities(vulns: Array<{
  scanId: number;
  type: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  description: string;
  recommendation: string;
}>): Promise<Vulnerability[]> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot create vulnerabilities: database not available, returning mock vulns");
    return vulns.map((v, idx) => ({
      id: Math.floor(Math.random() * 10000) + idx + 1,
      scanId: v.scanId,
      type: v.type,
      severity: v.severity,
      lineNumber: v.lineNumber,
      columnNumber: v.columnNumber,
      codeSnippet: v.codeSnippet,
      description: v.description,
      recommendation: v.recommendation,
      createdAt: new Date(),
      updatedAt: new Date(),
    }));
  }

  try {
    if (vulns.length === 0) return [];
    
    await db.insert(vulnerabilities).values(vulns);
    
    // Fetch the created records
    const created = await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, vulns[0].scanId));
    return created;
  } catch (error) {
    console.warn("[Database] Failed to create vulnerabilities, returning memory fallback:", error);
    return vulns.map((v, idx) => ({
      id: Math.floor(Math.random() * 10000) + idx + 1,
      scanId: v.scanId,
      type: v.type,
      severity: v.severity,
      lineNumber: v.lineNumber,
      columnNumber: v.columnNumber,
      codeSnippet: v.codeSnippet,
      description: v.description,
      recommendation: v.recommendation,
      createdAt: new Date(),
      updatedAt: new Date(),
    }));
  }
}

/**
 * Get vulnerabilities for a scan
 */
export async function getScanVulnerabilities(scanId: number): Promise<Vulnerability[]> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get vulnerabilities: database not available");
    return [];
  }

  return await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));
}
