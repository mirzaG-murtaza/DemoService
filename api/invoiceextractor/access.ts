import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  DemoAccessServiceError,
  evaluateInvoiceExtractorAccess,
} from "../../src/demoAccessService";
import { handleServiceError } from "../../src/http";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ message: "Method Not Allowed" });
  }

  const rawEmail = Array.isArray(req.query.email)
    ? req.query.email[0]
    : req.query.email;

  try {
    if (typeof rawEmail !== "string" || rawEmail.trim().length === 0) {
      throw new DemoAccessServiceError(
        "invalid_email",
        "An email address is required.",
        400
      );
    }

    const decision = await evaluateInvoiceExtractorAccess(rawEmail);
    return res.status(200).json({ data: decision });
  } catch (error) {
    return handleServiceError(res, error);
  }
}
