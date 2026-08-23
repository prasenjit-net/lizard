// Typed API client. Every backend failure — network, HTTP status, or the
// server's JSON error envelope — is normalized into ApiError, which the
// toast layer renders as an error notification bubble.

export interface UiConfig {
  appName: string;
  tagline: string;
  defaultTheme: string;
  repoUrl?: string | null;
}

export interface CaConfig {
  certValidityDays: number;
  rootValidityYears: number;
}

export interface ServerConfig {
  ui: UiConfig;
  ca: CaConfig;
  version: string;
  startedAtMs: number;
}

export interface Metrics {
  cpu: number;
  memory: number;
  requestsTotal: number;
  requestsPerMin: number;
  wsClients: number;
  uptimeSecs: number;
  timestampMs: number;
}

export interface Task {
  id: number;
  title: string;
  done: boolean;
  createdAt: string;
}

export interface ActivityLogEntry {
  id: number;
  kind: string;
  summary: string;
  createdAt: string;
  timestampMs: number;
}

export interface CaInfo {
  rootCertPem: string;
}

export interface Certificate {
  id: string;
  orderId: string;
  identifiers: string[];
  serial: string;
  status: "valid" | "revoked";
  issuedAt: string;
  notAfter: string;
  revokedAt: string | null;
  revocationReason: number | null;
}

export interface CertificateDetail extends Certificate {
  accountId: string;
  notBefore: string;
  notAfter: string;
  pemChain: string;
}

export type OrderStatus = "pending" | "ready" | "processing" | "valid" | "invalid";

export interface Order {
  id: string;
  accountId: string;
  status: OrderStatus;
  identifiers: string[];
  expires: string;
  createdAt: string;
  certificateId: string | null;
}

export interface ChallengeInfo {
  id: string;
  type: string;
  status: "pending" | "processing" | "valid" | "invalid";
  validatedAt: string | null;
  error: { type: string; detail: string } | null;
}

export interface AuthorizationInfo {
  id: string;
  identifier: string;
  status: "pending" | "valid" | "invalid" | "expired";
  expires: string;
  challenges: ChallengeInfo[];
}

export interface OrderDetail extends Order {
  error: { type: string; detail: string } | null;
  authorizations: AuthorizationInfo[];
}

export interface Account {
  id: string;
  jwkThumbprint: string;
  status: string;
  contact: string[];
  tosAgreed: boolean;
  createdAt: string;
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers as Record<string, string> | undefined),
      },
    });
  } catch {
    throw new ApiError("NETWORK", 0, "Cannot reach the server");
  }

  if (!res.ok) {
    // Prefer the backend's { error: { code, message } } envelope.
    let code = `HTTP_${res.status}`;
    let message = res.statusText || "Request failed";
    try {
      const body = (await res.json()) as {
        error?: { code?: string; message?: string };
      };
      if (body.error) {
        code = body.error.code ?? code;
        message = body.error.message ?? message;
      }
    } catch {
      /* body was not JSON — keep the status text */
    }
    throw new ApiError(code, res.status, message);
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const api = {
  config: () => request<ServerConfig>("/api/config"),
  health: () => request<{ status: string; version: string }>("/api/health"),
  metrics: () => request<Metrics>("/api/metrics"),
  listActivity: () => request<ActivityLogEntry[]>("/api/activity"),
  listTasks: () => request<Task[]>("/api/tasks"),
  createTask: (title: string) =>
    request<Task>("/api/tasks", { method: "POST", body: JSON.stringify({ title }) }),
  toggleTask: (id: number) => request<Task>(`/api/tasks/${id}/toggle`, { method: "POST" }),
  deleteTask: (id: number) => request<void>(`/api/tasks/${id}`, { method: "DELETE" }),
  /** Always fails server-side — demonstrates the error pipeline. */
  errorDemo: (kind: string) => request<never>(`/api/error-demo?kind=${kind}`),
  /** Hits an endpoint that does not exist — demonstrates the JSON 404. */
  missing: () => request<never>("/api/this-endpoint-does-not-exist"),
  caInfo: () => request<CaInfo>("/api/ca"),
  listCertificates: () => request<Certificate[]>("/api/certificates"),
  getCertificate: (id: string) => request<CertificateDetail>(`/api/certificates/${id}`),
  revokeCertificate: (id: string) =>
    request<void>(`/api/certificates/${id}/revoke`, { method: "POST" }),
  listOrders: () => request<Order[]>("/api/orders"),
  getOrder: (id: string) => request<OrderDetail>(`/api/orders/${id}`),
  listAccounts: () => request<Account[]>("/api/accounts"),
};
