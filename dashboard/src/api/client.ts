const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(
  /\/$/,
  "",
);

export class ApiError extends Error {
  status: number;
  details?: string;
  constructor(message: string, status: number, details?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  if (!response.ok) {
    const apiMessage =
      typeof body === "object" && body && "error" in body
        ? String((body as { error: unknown }).error)
        : text;
    throw new ApiError(
      `Request failed (${response.status})`,
      response.status,
      apiMessage || undefined,
    );
  }
  return body as T;
}

export const api = {
  health: () => request<{ status: string }>("/health"),
  getTargets: () => request<import("./types").Target[]>("/api/targets"),
  getTarget: (id: string) =>
    request<import("./types").Target>(`/api/targets/${encodeURIComponent(id)}`),
  createTarget: (input: import("./types").TargetInput) =>
    request<import("./types").Target>("/api/targets", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  updateTarget: (id: string, input: import("./types").TargetUpdateInput) =>
    request<import("./types").Target>(
      `/api/targets/${encodeURIComponent(id)}`,
      { method: "PUT", body: JSON.stringify(input) },
    ),
  scanTarget: (id: string) =>
    request<import("./types").Scan>(`/api/scans/${encodeURIComponent(id)}`, {
      method: "POST",
    }),
  getLatestScan: (id: string) =>
    request<import("./types").Scan>(
      `/api/scans/targets/${encodeURIComponent(id)}/latest`,
    ),
  getRecentScans: (params: URLSearchParams) =>
    request<import("./types").RecentScansResponse>(
      `/api/scans/recent?${params.toString()}`,
    ),
};
