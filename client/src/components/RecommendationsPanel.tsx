import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { Streamdown } from "streamdown";
import { trpc } from "@/lib/trpc";
import { CheckCircle } from "lucide-react";

interface Vulnerability {
  type: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  description: string;
  recommendation: string;
}

interface RecommendationsPanelProps {
  vulnerability: Vulnerability;
}

export default function RecommendationsPanel({ vulnerability }: RecommendationsPanelProps) {
  const [recommendations, setRecommendations] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);

  const recommendMutation = trpc.scan.generateRecommendations.useMutation({
    onSuccess: (result) => {
      setRecommendations(result.recommendations);
      setIsLoading(false);
    },
    onError: () => {
      setIsLoading(false);
    },
  });

  useEffect(() => {
    setIsLoading(true);
    recommendMutation.mutate({
      type: vulnerability.type,
      codeSnippet: vulnerability.codeSnippet,
      recommendation: vulnerability.recommendation,
    });
  }, [vulnerability]);

  return (
    <Card className="border-slate-700 bg-slate-800/50">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2">
          <CheckCircle className="w-5 h-5 text-green-500" />
          Remediation Recommendations
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Spinner className="h-6 w-6 mr-2" />
            <span className="text-slate-400">Generating recommendations...</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded border border-slate-700 p-4">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">Vulnerable Code:</h3>
              <pre className="text-slate-300 text-xs font-mono whitespace-pre-wrap break-words overflow-auto max-h-32">
                {vulnerability.codeSnippet}
              </pre>
            </div>

            <div className="bg-green-500/10 border border-green-500/30 rounded p-4">
              <h3 className="text-sm font-semibold text-green-400 mb-3">How to Fix:</h3>
              <div className="text-slate-300 text-sm prose prose-invert max-w-none">
                <Streamdown>{recommendations}</Streamdown>
              </div>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/30 rounded p-4">
              <h3 className="text-sm font-semibold text-blue-400 mb-2">Quick Reference:</h3>
              <p className="text-slate-300 text-sm">{vulnerability.recommendation}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
