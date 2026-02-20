import { useCallback, useRef, useState } from "react";
import { copyToClipboard } from "@/lib/clipboard.ts";

export function useCopyFeedback(durationMs = 2000): {
  copied: boolean;
  onCopy: (text: string) => Promise<void>;
} {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const onCopy = useCallback(
    async (text: string) => {
      const ok = await copyToClipboard(text);
      if (ok) {
        setCopied(true);
        clearTimeout(timerRef.current);
        timerRef.current = setTimeout(() => setCopied(false), durationMs);
      }
    },
    [durationMs],
  );

  return { copied, onCopy };
}
