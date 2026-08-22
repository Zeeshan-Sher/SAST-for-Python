import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { Streamdown } from "streamdown";
import { trpc } from "@/lib/trpc";

interface Vulnerability {
  type: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  description: string;
  recommendation: string;
}

interface ExplanationPanelProps {
  vulnerability: Vulnerability;
}

export default function ExplanationPanel({ vulnerability }: ExplanationPanelProps) {
  const [explanation, setExplanation] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);

  const explainMutation = trpc.scan.explainVulnerability.useMutation({
    onSuccess: (result) => {
      setExplanation(result.explanation);
      setIsLoading(false);
    },
    onError: () => {
      setIsLoading(false);
    },
  });

  useEffect(() => {
    setIsLoading(true);
    explainMutation.mutate({
      type: vulnerability.type,
      codeSnippet: vulnerability.codeSnippet,
      description: vulnerability.description,
    });
  }, [vulnerability]);

  return (
    <Card className="border-slate-700 bg-slate-800/50">
      <CardHeader>
        <CardTitle className="text-white">
          {vulnerability.type} - Detailed Explanation
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Spinner className="h-6 w-6 mr-2" />
            <span className="text-slate-400">Generating explanation...</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded border border-slate-700 p-4">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">Code Snippet:</h3>
              <pre className="text-slate-300 text-xs font-mono whitespace-pre-wrap break-words overflow-auto max-h-32">
                {vulnerability.codeSnippet}
              </pre>
            </div>

            <div className="bg-slate-900 rounded border border-slate-700 p-4">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">Explanation:</h3>
              <div className="text-slate-300 text-sm prose prose-invert max-w-none">
                <Streamdown>{explanation}</Streamdown>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="bg-red-500/10 border border-red-500/30 rounded p-3">
                <h4 className="text-xs font-semibold text-red-400 mb-1">Severity</h4>
                <p className="text-sm text-red-300">{vulnerability.severity}</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded p-3">
                <h4 className="text-xs font-semibold text-blue-400 mb-1">Line Number</h4>
                <p className="text-sm text-blue-300">{vulnerability.lineNumber}</p>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
