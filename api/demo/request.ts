import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  DemoAccessServiceError,
  submitDemoRequest,
  type DemoRequestPayload,
} from "../../src/demoAccessService";
import { handleServiceError, readJsonBody } from "../../src/http";

function ensurePayload(
  payload: Partial<DemoRequestPayload>
): asserts payload is DemoRequestPayload {
  const required: Array<keyof DemoRequestPayload> = [
    "name",
    "email",
    "designation",
    "companySize",
    "branches",
    "application",
  ];

  const missing = required.filter((field) => {
    const value = payload[field];
    return typeof value !== "string" || value.trim().length === 0;
  });

  if (missing.length > 0) {
    throw new DemoAccessServiceError(
      "validation_error",
      `Missing required fields: ${missing.join(", ")}`,
      400,
      { missing }
    );
  }
}

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ message: "Method Not Allowed" });
  }

  try {
    const payload = await readJsonBody<Partial<DemoRequestPayload>>(req);
    ensurePayload(payload);
    payload.application = payload.application.trim().toLowerCase();

    const result = await submitDemoRequest(payload);
    return res.status(200).json({ data: result });
  } catch (error) {
    return handleServiceError(res, error);
  }
}
