import { memo, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import type { StreamLine } from "@/lib/types.ts";

interface AgentStreamProps {
  lines: StreamLine[];
  connected: boolean;
  done: boolean;
}

const LINE_COLORS: Record<StreamLine["type"], string> = {
  info: "text-terminal-muted",
  finding: "text-terminal-yellow",
  error: "text-terminal-red",
  step: "text-terminal-blue",
  progress: "text-terminal-muted",
};

function formatTime(date: Date): string {
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// Per-line memo: each line's props (id/text/type/timestamp) are stable
// once the line is appended, so on re-render only the brand-new line
// reconciles. Without this, every SSE event re-renders all 500 lines.
interface LineRowProps {
  text: string;
  type: StreamLine["type"];
  timestamp: Date;
}

const LineRow = memo(function LineRow({ text, type, timestamp }: LineRowProps) {
  return (
    <div className="terminal-line">
      <span className="terminal-time">{formatTime(timestamp)}</span>
      <span className={`flex-1 text-xs leading-relaxed break-all ${LINE_COLORS[type]}`}>
        {type === "finding" ? (
          <span className="font-medium">{text}</span>
        ) : type === "step" ? (
          <span className="font-semibold">{text}</span>
        ) : (
          text
        )}
      </span>
    </div>
  );
});

export function AgentStream({ lines, connected, done }: AgentStreamProps) {
  const { t } = useTranslation();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="terminal" data-testid="agent-stream">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/10">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-danger/80" />
            <span className="w-3 h-3 rounded-full bg-warning/80" />
            <span className="w-3 h-3 rounded-full bg-success/80" />
          </div>
          <span className="text-xs text-terminal-muted ml-2">{t("results.terminal")}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className={`w-2 h-2 rounded-full ${
              done ? "bg-terminal-muted" : connected ? "bg-success animate-pulse" : "bg-warning animate-pulse"
            }`}
          />
          <span className="text-xs text-terminal-muted">
            {done
              ? t("results.streamComplete")
              : connected
                ? t("results.connected")
                : t("results.connecting")}
          </span>
        </div>
      </div>

      {/* Lines */}
      <div ref={scrollRef} className="max-h-[400px] overflow-y-auto py-1">
        {lines.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-terminal-muted text-sm">
            <div className="w-4 h-4 border-2 border-terminal-muted/30 border-t-terminal-muted rounded-full animate-spin mr-3" />
            {t("results.waitingAgents")}
          </div>
        ) : (
          lines.map((line) => (
            <LineRow
              key={line.id}
              text={line.text}
              type={line.type}
              timestamp={line.timestamp}
            />
          ))
        )}
      </div>
    </div>
  );
}
