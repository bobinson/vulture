interface ScoreCardProps {
  label: string;
  score: number;
}

function getScoreColor(score: number): string {
  if (score >= 80) return "text-success";
  if (score >= 50) return "text-warning";
  return "text-danger";
}

function getStrokeColor(score: number): string {
  if (score >= 80) return "#2DA44E";
  if (score >= 50) return "#BF8700";
  return "#CF222E";
}

export function ScoreCard({ label, score }: ScoreCardProps) {
  const circumference = 2 * Math.PI * 40;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="card px-4 py-4 flex flex-col items-center gap-2">
      <div className="relative w-20 h-20">
        <svg className="w-20 h-20 -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50" cy="50" r="40"
            fill="none"
            stroke="var(--color-border)"
            strokeWidth="6"
          />
          <circle
            cx="50" cy="50" r="40"
            fill="none"
            stroke={getStrokeColor(score)}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="animate-score-ring"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-lg font-semibold tabular-nums ${getScoreColor(score)}`}>
            {Math.round(score)}
          </span>
        </div>
      </div>
      <p className="text-[11px] font-semibold text-muted tracking-wider">{label}</p>
    </div>
  );
}
