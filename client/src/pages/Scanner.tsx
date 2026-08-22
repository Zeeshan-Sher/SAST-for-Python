import { useState, useRef } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Spinner } from "@/components/ui/spinner";
import { AlertTriangle, Upload, Code, AlertCircle } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import VulnerabilityTable from "@/components/VulnerabilityTable";
import SecurityScoreCard from "@/components/SecurityScoreCard";
import RiskLevelCard from "@/components/RiskLevelCard";
import ExplanationPanel from "@/components/ExplanationPanel";
import RecommendationsPanel from "@/components/RecommendationsPanel";

interface ScanResult {
  scanId: number;
  fileName: string;
  securityScore: number;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  vulnerabilityCount: number;
  vulnerabilities: Array<{
    type: string;
    severity: "Critical" | "High" | "Medium" | "Low";
    lineNumber: number;
    columnNumber: number;
    codeSnippet: string;
    description: string;
    recommendation: string;
  }>;
}

export default function Scanner() {
  const { user, isAuthenticated } = useAuth();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploadedCode, setUploadedCode] = useState<string>("");
  const [fileName, setFileName] = useState<string>("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const analyzeMutation = trpc.scan.analyze.useMutation({
    onSuccess: (result) => {
      setScanResult(result);
      toast.success("Code analysis complete!");
    },
    onError: (error) => {
      toast.error(`Analysis failed: ${error.message}`);
    },
  });

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Authentication Required</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-foreground/60">Please log in to use the vulnerability scanner.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const handleFileSelect = (file: File) => {
    if (!file.name.endsWith(".py")) {
      toast.error("Please select a Python (.py) file");
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setUploadedCode(content);
      setFileName(file.name);
      setScanResult(null);
    };
    reader.onerror = () => {
      toast.error("Failed to read file");
    };
    reader.readAsText(file);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleAnalyze = async () => {
    if (!uploadedCode || !fileName) {
      toast.error("Please upload a Python file first");
      return;
    }

    analyzeMutation.mutate({
      fileName,
      sourceCode: uploadedCode,
    });
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "Critical":
        return "bg-red-500/10 text-red-700 border-red-200";
      case "High":
        return "bg-orange-500/10 text-orange-700 border-orange-200";
      case "Medium":
        return "bg-yellow-500/10 text-yellow-700 border-yellow-200";
      case "Low":
        return "bg-green-500/10 text-green-700 border-green-200";
      default:
        return "bg-gray-500/10 text-gray-700 border-gray-200";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <AlertTriangle className="w-8 h-8 text-red-500" />
            <h1 className="text-3xl font-bold text-white">Python Security Scanner</h1>
          </div>
          <p className="text-slate-400">Analyze Python code for common security vulnerabilities</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Upload and Code Display */}
          <div className="lg:col-span-2 space-y-6">
            {/* Upload Area */}
            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="text-white">Upload Python File</CardTitle>
                <CardDescription>Drag and drop or click to select a .py file</CardDescription>
              </CardHeader>
              <CardContent>
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
                    isDragging
                      ? "border-blue-500 bg-blue-500/10"
                      : "border-slate-600 bg-slate-700/30 hover:border-slate-500"
                  }`}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="w-12 h-12 mx-auto mb-4 text-slate-400" />
                  <p className="text-white font-medium mb-2">Drop your Python file here</p>
                  <p className="text-slate-400 text-sm">or click to browse</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".py"
                    onChange={handleFileInputChange}
                    className="hidden"
                  />
                </div>

                {fileName && (
                  <div className="mt-4 p-3 bg-green-500/10 border border-green-500/30 rounded text-green-400 text-sm">
                    ✓ File selected: {fileName}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Code Display */}
            {uploadedCode && (
              <Card className="border-slate-700 bg-slate-800/50">
                <CardHeader>
                  <CardTitle className="text-white text-lg">Code Preview</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="bg-slate-900 rounded border border-slate-700 p-4 max-h-96 overflow-auto">
                    <pre className="text-slate-300 text-sm font-mono whitespace-pre-wrap break-words">
                      {uploadedCode}
                    </pre>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Analyze Button */}
            {uploadedCode && (
              <Button
                onClick={handleAnalyze}
                disabled={analyzeMutation.isPending}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white py-6 text-lg font-semibold"
              >
                {analyzeMutation.isPending ? (
                  <>
                    <Spinner className="mr-2 h-5 w-5" />
                    Analyzing Code...
                  </>
                ) : (
                  <>
                    <Code className="mr-2 h-5 w-5" />
                    Analyze Code
                  </>
                )}
              </Button>
            )}
          </div>

          {/* Right Column - Results Summary */}
          <div className="space-y-6">
            {scanResult ? (
              <>
                {/* Security Score Card */}
                <SecurityScoreCard score={scanResult.securityScore} />

                {/* Risk Level Card */}
                <RiskLevelCard level={scanResult.riskLevel} />

                {/* Vulnerability Count */}
                <Card className="border-slate-700 bg-slate-800/50">
                  <CardHeader>
                    <CardTitle className="text-white text-sm">Vulnerabilities Found</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-4xl font-bold text-white mb-2">
                      {scanResult.vulnerabilityCount}
                    </div>
                    <p className="text-slate-400 text-sm">
                      {scanResult.vulnerabilityCount === 0
                        ? "No vulnerabilities detected"
                        : `${scanResult.vulnerabilityCount} issue${scanResult.vulnerabilityCount !== 1 ? "s" : ""} found`}
                    </p>
                  </CardContent>
                </Card>
              </>
            ) : (
              <Card className="border-slate-700 bg-slate-800/50">
                <CardHeader>
                  <CardTitle className="text-white text-sm">Ready to Scan</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-slate-400 text-sm">
                    Upload a Python file and click "Analyze Code" to get started.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        {/* Results Section */}
        {scanResult && scanResult.vulnerabilityCount > 0 && (
          <div className="mt-8 space-y-6">
            <Tabs defaultValue="vulnerabilities" className="w-full">
              <TabsList className="grid w-full grid-cols-3 bg-slate-800 border border-slate-700">
                <TabsTrigger value="vulnerabilities" className="text-white">
                  Vulnerabilities
                </TabsTrigger>
                <TabsTrigger value="explanation" className="text-white">
                  Explanation
                </TabsTrigger>
                <TabsTrigger value="recommendations" className="text-white">
                  Recommendations
                </TabsTrigger>
              </TabsList>

              <TabsContent value="vulnerabilities" className="space-y-4">
                <VulnerabilityTable
                  vulnerabilities={scanResult.vulnerabilities}
                  onSelectVulnerability={setSelectedVulnerability}
                  selectedId={selectedVulnerability}
                />
              </TabsContent>

              <TabsContent value="explanation" className="space-y-4">
                {selectedVulnerability !== null && scanResult.vulnerabilities[selectedVulnerability] ? (
                  <ExplanationPanel
                    vulnerability={scanResult.vulnerabilities[selectedVulnerability]}
                  />
                ) : (
                  <Alert className="border-slate-700 bg-slate-800/50">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription className="text-slate-400">
                      Select a vulnerability from the table to view its detailed explanation
                    </AlertDescription>
                  </Alert>
                )}
              </TabsContent>

              <TabsContent value="recommendations" className="space-y-4">
                {selectedVulnerability !== null && scanResult.vulnerabilities[selectedVulnerability] ? (
                  <RecommendationsPanel
                    vulnerability={scanResult.vulnerabilities[selectedVulnerability]}
                  />
                ) : (
                  <Alert className="border-slate-700 bg-slate-800/50">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription className="text-slate-400">
                      Select a vulnerability from the table to view remediation recommendations
                    </AlertDescription>
                  </Alert>
                )}
              </TabsContent>
            </Tabs>
          </div>
        )}

        {/* No Vulnerabilities Message */}
        {scanResult && scanResult.vulnerabilityCount === 0 && (
          <div className="mt-8">
            <Alert className="border-green-700/50 bg-green-500/10">
              <AlertCircle className="h-4 w-4 text-green-500" />
              <AlertDescription className="text-green-400">
                Excellent! No vulnerabilities detected in the analyzed code.
              </AlertDescription>
            </Alert>
          </div>
        )}
      </div>
    </div>
  );
}
