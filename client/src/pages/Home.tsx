import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Code, Shield, Zap } from "lucide-react";
import { useLocation } from "wouter";
import { getLoginUrl } from "@/const";

export default function Home() {
  const { user, isAuthenticated } = useAuth();
  const [, navigate] = useLocation();

  if (isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="max-w-7xl mx-auto px-4 py-16">
          {/* Welcome Header */}
          <div className="text-center mb-12">
            <div className="flex items-center justify-center gap-3 mb-4">
              <AlertTriangle className="w-10 h-10 text-red-500" />
              <h1 className="text-4xl font-bold text-white">Python Security Scanner</h1>
            </div>
            <p className="text-slate-400 text-lg">
              Analyze your Python code for security vulnerabilities instantly
            </p>
          </div>

          {/* Quick Start Card */}
          <div className="grid md:grid-cols-2 gap-8 mb-12">
            <Card className="border-slate-700 bg-slate-800/50 md:col-span-2">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  Quick Start
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-slate-300">
                  Welcome! Get started by uploading a Python file to scan for security vulnerabilities.
                </p>
                <Button
                  onClick={() => navigate("/scanner")}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 text-lg font-semibold"
                >
                  <Code className="mr-2 h-5 w-5" />
                  Go to Scanner
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Features Grid */}
          <div className="grid md:grid-cols-3 gap-6">
            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="text-white text-lg flex items-center gap-2">
                  <Shield className="w-5 h-5 text-green-500" />
                  Comprehensive Detection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-sm">
                  Detects SQL Injection, Command Injection, Hardcoded Secrets, Dangerous Functions, and XSS patterns
                </p>
              </CardContent>
            </Card>

            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="text-white text-lg flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-orange-500" />
                  Risk Assessment
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-sm">
                  Get a security score (0-100) and risk level (Critical/High/Medium/Low) for your code
                </p>
              </CardContent>
            </Card>

            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="text-white text-lg flex items-center gap-2">
                  <Code className="w-5 h-5 text-blue-500" />
                  AI-Powered Insights
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-sm">
                  Get detailed explanations and remediation recommendations for each vulnerability
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  }

  // Not authenticated - show login prompt
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center px-4">
      <Card className="w-full max-w-md border-slate-700 bg-slate-800/50">
        <CardHeader>
          <div className="flex items-center gap-3 mb-4">
            <AlertTriangle className="w-8 h-8 text-red-500" />
            <CardTitle className="text-white text-2xl">Python Security Scanner</CardTitle>
          </div>
          <CardDescription className="text-slate-400">
            Analyze your Python code for security vulnerabilities
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-slate-300">
            Sign in to start scanning your Python files for security issues.
          </p>
          <Button
            onClick={() => window.location.href = getLoginUrl()}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white py-6 text-lg font-semibold"
          >
            Sign In with Manus
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
