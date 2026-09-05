// Simplified database module for Vercel deployment
// Uses in-memory storage instead of actual database

import type { User } from "../../drizzle/schema";

// In-memory storage
const users = new Map<number, User>();
const codeScans = new Map<number, any>();
const vulnerabilities = new Map<number, any[]>();

let userIdCounter = 1;
let scanIdCounter = 1;

// Initialize with a default user
users.set(1, {
  id: 1,
  openId: "standalone-user",
  name: "Security Engineer",
  email: "security@local.test",
  loginMethod: "standalone",
  role: "admin" as const,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
});

export async function upsertUser(data: Partial<User> & { openId: string }): Promise<User | null> {
  try {
    const existingUser = Array.from(users.values()).find(u => u.openId === data.openId);
    
    if (existingUser) {
      const updated = { ...existingUser, ...data, updatedAt: new Date() };
      users.set(existingUser.id, updated);
      return updated;
    }
    
    const newUser: User = {
      id: userIdCounter++,
      openId: data.openId,
      name: data.name || "User",
      email: data.email || null,
      loginMethod: data.loginMethod || null,
      role: "user" as const,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };
    
    users.set(newUser.id, newUser);
    return newUser;
  } catch (error) {
    console.error("Failed to upsert user:", error);
    return null;
  }
}

export async function getUserByOpenId(openId: string): Promise<User | null> {
  try {
    const user = Array.from(users.values()).find(u => u.openId === openId);
    return user || null;
  } catch (error) {
    console.error("Failed to get user:", error);
    return null;
  }
}

export async function createCodeScan(data: any): Promise<any> {
  try {
    const scan = {
      id: scanIdCounter++,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    codeScans.set(scan.id, scan);
    return scan;
  } catch (error) {
    console.error("Failed to create code scan:", error);
    return null;
  }
}

export async function createVulnerabilities(vulns: any[]): Promise<any[]> {
  try {
    return vulns.map((v, idx) => ({
      id: idx + Math.random(),
      ...v,
      createdAt: new Date(),
    }));
  } catch (error) {
    console.error("Failed to create vulnerabilities:", error);
    return [];
  }
}

export async function getScanVulnerabilities(scanId: number): Promise<any[]> {
  try {
    return vulnerabilities.get(scanId) || [];
  } catch (error) {
    console.error("Failed to get vulnerabilities:", error);
    return [];
  }
}

export async function getUserCodeScans(userId: number): Promise<any[]> {
  try {
    const userScans = Array.from(codeScans.values()).filter(scan => scan.userId === userId);
    return userScans;
  } catch (error) {
    console.error("Failed to get user scans:", error);
    return [];
  }
}

export async function getCodeScanById(scanId: number): Promise<any> {
  try {
    return codeScans.get(scanId) || null;
  } catch (error) {
    console.error("Failed to get code scan:", error);
    return null;
  }
}
