import { int, mysqlEnum, mysqlTable, text, timestamp, varchar, json } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Stores Python code scans and analysis results
 */
export const codeScans = mysqlTable("codeScans", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  fileName: varchar("fileName", { length: 255 }).notNull(),
  sourceCode: text("sourceCode").notNull(),
  securityScore: int("securityScore").notNull().default(100),
  riskLevel: mysqlEnum("riskLevel", ["Critical", "High", "Medium", "Low"]).notNull().default("Low"),
  vulnerabilityCount: int("vulnerabilityCount").notNull().default(0),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type CodeScan = typeof codeScans.$inferSelect;
export type InsertCodeScan = typeof codeScans.$inferInsert;

/**
 * Stores individual vulnerabilities detected in code scans
 */
export const vulnerabilities = mysqlTable("vulnerabilities", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  type: varchar("type", { length: 100 }).notNull(), // SQL Injection, Command Injection, etc.
  severity: mysqlEnum("severity", ["Critical", "High", "Medium", "Low"]).notNull(),
  lineNumber: int("lineNumber").notNull(),
  columnNumber: int("columnNumber").default(0),
  codeSnippet: text("codeSnippet").notNull(),
  description: text("description"),
  recommendation: text("recommendation"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = typeof vulnerabilities.$inferInsert;
