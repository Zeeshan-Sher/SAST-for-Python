import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield } from "lucide-react";

interface SecurityScoreCardProps {
  score: number;
}

export default function SecurityScoreCard({ score }: SecurityScoreCardProps) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-500";
    if (score >= 60) return "text-yellow-500";
    if (score >= 40) return "text-orange-500";
    return "text-red-500";
  };

  const getScoreLabel = (score: number) => {
    if (score >= 80) return "Excellent";
    if (score >= 60) return "Good";
    if (score >= 40) return "Fair";
    return "Poor";
  };

  return (
    <Card className="border-slate-700 bg-slate-800/50">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2 text-sm">
          <Shield className="w-4 h-4" />
          Security Score
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-center">
          <div className={`text-5xl font-bold mb-2 ${getScoreColor(score)}`}>
            {score}
          </div>
          <p className="text-slate-400 text-sm">{getScoreLabel(score)}</p>
          <div className="mt-4 w-full bg-slate-700 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all ${getScoreColor(score).replace('text-', 'bg-')}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
