// Typed API client. The browser talks to the backend API only; it never touches files.
import type { ErrorDetail } from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: ErrorDetail[];
  readonly correlationId: string | null;

  constructor(status: number, code: string, message: string, details: ErrorDetail[] = [], correlationId: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.correlationId = correlationId;
  }

  /** Field-level messages keyed by the last path segment (e.g. "window_end"). */
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const d of this.details) {
      const field = d.loc.filter((p) => p !== "body").join(".");
      if (field && !(field in out)) out[field] = d.message;
    }
    return out;
  }

  /** A single human-readable sentence for toasts/alerts. */
  describe(): string {
    if (this.details.length === 0) return this.message;
    const parts = this.details.slice(0, 3).map((d) => {
      const field = d.loc.filter((p) => p !== "body").join(" › ");
      return field ? `${field}: ${d.message}` : d.message;
    });
    return `${this.message} ${parts.join("; ")}`;
  }
}

type Query = Record<string, string | number | boolean | string[] | undefined | null>;

function buildUrl(path: string, query?: Query): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => params.append(key, v));
    else params.append(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export async function request<T>(method: string, path: string, options: { query?: Query; body?: unknown } = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(buildUrl(path, options.query), {
      method,
      headers: options.body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the Workbench backend. Is `python -m app` running?");
  }
  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }
  if (!response.ok) {
    const err = (payload as { error?: { code?: string; message?: string; details?: ErrorDetail[]; correlation_id?: string | null } } | null)?.error;
    throw new ApiError(
      response.status,
      err?.code ?? "http_error",
      err?.message ?? `Request failed with status ${response.status}`,
      err?.details ?? [],
      err?.correlation_id ?? response.headers.get("x-request-id"),
    );
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, { query }),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, { body }),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, { body }),
  delete: <T>(path: string, query?: Query) => request<T>("DELETE", path, { query }),
};
