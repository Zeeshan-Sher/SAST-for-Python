import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle } from "lucide-react";

interface RiskLevelCardProps {
  level: "Critical" | "High" | "Medium" | "Low";
}

export default function RiskLevelCard({ level }: RiskLevelCardProps) {
  const getRiskColor = (level: string) => {
    switch (level) {
      case "Critical":
        return "text-red-500 bg-red-500/10";
      case "High":
        return "text-orange-500 bg-orange-500/10";
      case "Medium":
        return "text-yellow-500 bg-yellow-500/10";
      case "Low":
        return "text-green-500 bg-green-500/10";
      default:
        return "text-gray-500 bg-gray-500/10";
    }
  };

  const getRiskDescription = (level: string) => {
    switch (level) {
      case "Critical":
        return "Immediate action required";
      case "High":
        return "Should be addressed soon";
      case "Medium":
        return "Consider fixing";
      case "Low":
        return "Minor issues";
      default:
        return "Unknown risk";
    }
  };

  return (
    <Card className="border-slate-700 bg-slate-800/50">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2 text-sm">
          <AlertTriangle className="w-4 h-4" />
          Risk Level
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`p-4 rounded-lg text-center ${getRiskColor(level)}`}>
          <div className="text-2xl font-bold mb-1">{level}</div>
          <p className="text-xs opacity-80">{getRiskDescription(level)}</p>
        </div>
      </CardContent>
    </Card>
  );
}
