import type {
  AgentInfo,
  Audit,
  AuditMemory,
  BrowseResponse,
  CacheCheckResponse,
  CreateAuditRequest,
  CreateSourceRequest,
  DashboardStats,
  FindingLineage,
  LineageEvent,
  MemoryEdge,
  MemoryWithEdges,
  Source,
} from "./types.ts";
import type { User } from "./auth.tsx";

const API_BASE = import.meta.env.VITE_API_URL ?? "";

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("vulture_token");
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
      ...options?.headers,
    },
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "Unknown error");
    throw new ApiError(response.status, text);
  }
  return response.json() as Promise<T>;
}

interface AuthResponse {
  token: string;
  user: User;
}

interface LoginRequest {
  email: string;
  password: string;
}

interface RegisterRequest {
  email: string;
  password: string;
  name: string;
  team_name?: string;
}

export const api = {
  // Auth
  localSession(): Promise<AuthResponse> {
    return request<AuthResponse>("/api/auth/local-session");
  },

  login(data: LoginRequest): Promise<AuthResponse> {
    return request<AuthResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  register(data: RegisterRequest): Promise<AuthResponse> {
    return request<AuthResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  me(token: string): Promise<User> {
    return request<User>("/api/auth/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
  },

  // Sources
  createSource(data: CreateSourceRequest): Promise<Source> {
    return request<Source>("/api/sources", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getSource(id: string): Promise<Source> {
    return request<Source>(`/api/sources/${id}`);
  },

  // Audits
  createAudit(data: CreateAuditRequest): Promise<Audit> {
    return request<Audit>("/api/audits", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getAudit(id: string): Promise<Audit> {
    return request<Audit>(`/api/audits/${id}`);
  },

  listAudits(limit = 20, offset = 0): Promise<Audit[]> {
    return request<Audit[]>(`/api/audits?limit=${limit}&offset=${offset}`);
  },

  getStats(): Promise<DashboardStats> {
    return request<DashboardStats>("/api/stats");
  },

  // Agents
  getAgents(): Promise<AgentInfo[]> {
    return request<AgentInfo[]>("/api/agents");
  },

  checkCache(sourceId: string, types: string[]): Promise<CacheCheckResponse> {
    return request<CacheCheckResponse>(
      `/api/audits/cache?source_id=${sourceId}&types=${types.join(",")}`,
    );
  },

  // Memories
  searchMemories(query: string, limit = 20): Promise<AuditMemory[]> {
    return request<AuditMemory[]>(
      `/api/memories/search?q=${encodeURIComponent(query)}&limit=${limit}`,
    );
  },

  listMemories(auditId: string): Promise<AuditMemory[]> {
    return request<AuditMemory[]>(
      `/api/memories?audit_id=${auditId}`,
    );
  },

  getMemoryWithEdges(id: string): Promise<MemoryWithEdges> {
    return request<MemoryWithEdges>(`/api/memories/${id}`);
  },

  getMemoryEdges(id: string): Promise<MemoryEdge[]> {
    return request<MemoryEdge[]>(`/api/memories/${id}/edges`);
  },

  updateRemediation(id: string, status: string, notes: string): Promise<{ status: string }> {
    return request<{ status: string }>(`/api/memories/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status, notes }),
    });
  },

  // Lineage
  getLineage(id: string): Promise<FindingLineage> {
    return request<FindingLineage>(`/api/lineage/${id}`);
  },

  listLineage(sourcePath: string, status?: string, limit = 50, offset = 0): Promise<FindingLineage[]> {
    let url = `/api/lineage?source_path=${encodeURIComponent(sourcePath)}&limit=${limit}&offset=${offset}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    return request<FindingLineage[]>(url);
  },

  getLineageTimeline(id: string): Promise<LineageEvent[]> {
    return request<LineageEvent[]>(`/api/lineage/${id}/timeline`);
  },

  updateLineageStatus(id: string, status: string, notes?: string, ticketUrl?: string): Promise<FindingLineage> {
    return request<FindingLineage>(`/api/lineage/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status, notes, ticket_url: ticketUrl }),
    });
  },

  getAuditLineage(auditId: string): Promise<FindingLineage[]> {
    return request<FindingLineage[]>(`/api/audits/${auditId}/lineage`);
  },

  getStreamUrl(auditId: string): string {
    const token = localStorage.getItem("vulture_token");
    const base = `${API_BASE}/api/audits/${auditId}/stream`;
    return token ? `${base}?token=${encodeURIComponent(token)}` : base;
  },

  // Filesystem browsing
  browseFilesystem(path: string): Promise<BrowseResponse> {
    return request<BrowseResponse>(
      `/api/filesystem/browse?path=${encodeURIComponent(path)}`,
    );
  },

  healthCheck(): Promise<{ status: string }> {
    return request<{ status: string }>("/health");
  },
};

export { ApiError };
