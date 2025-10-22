import type { VercelRequest, VercelResponse } from "@vercel/node";
import { DemoAccessServiceError } from "./demoAccessService";

export async function readJsonBody<T = unknown>(
  req: VercelRequest
): Promise<T> {
  if (req.body) {
    if (typeof req.body === "string") {
      return JSON.parse(req.body) as T;
    }
    return req.body as T;
  }

  const chunks: Uint8Array[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }

  if (chunks.length === 0) {
    return {} as T;
  }

  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) {
    return {} as T;
  }
  return JSON.parse(raw) as T;
}

export function sendJson<T>(res: VercelResponse, status: number, payload: T) {
  res.status(status).json(payload);
}

export function handleServiceError(
  res: VercelResponse,
  error: unknown
): VercelResponse {
  if (error instanceof DemoAccessServiceError) {
    return res.status(error.status).json({
      code: error.code,
      message: error.message,
      details: error.details ?? null,
    });
  }

  console.error("[DemoAccessService] Unexpected error", error);
  return res.status(500).json({
    code: "unexpected_error",
    message: "An unexpected error occurred",
  });
}
