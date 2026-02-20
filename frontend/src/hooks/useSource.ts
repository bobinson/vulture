import { useCallback, useState } from "react";
import { api } from "@/lib/api.ts";
import type { Source } from "@/lib/types.ts";

export function validateGitUrl(url: string): string | null {
  if (!url.trim()) return "URL is required";
  if (!/^https?:\/\/.+\.git$|^git@.+:.+\.git$/.test(url)) {
    return "Please enter a valid Git URL";
  }
  return null;
}

export function validateLocalPath(path: string): string | null {
  if (!path.trim()) return "Path is required";
  if (!path.startsWith("/")) {
    return "Please enter an absolute path (starting with /)";
  }
  return null;
}

export function useSource() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submitSource = useCallback(async (type: "git" | "local", value: string) => {
    setLoading(true);
    setError(null);
    try {
      const body = type === "git" ? { type, url: value } : { type, path: value };
      const result = await api.createSource(body);
      return result as Source;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to submit source";
      setError(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { submitSource, loading, error };
}
