import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  DemoAccessServiceError,
  logDemoTokenAccessEvent,
} from "../../src/demoAccessService";
import { handleServiceError, readJsonBody } from "../../src/http";

type LogAccessBody = {
  contactId?: string;
  email?: string | null;
  name?: string | null;
  designation?: string | null;
  companySize?: string | null;
  branches?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  application?: string | null;
};

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ message: "Method Not Allowed" });
  }

  try {
    const body = await readJsonBody<LogAccessBody>(req);
    const contactId = body.contactId?.trim();

    if (!contactId) {
      throw new DemoAccessServiceError(
        "validation_error",
        "contactId is required",
        400
      );
    }

    const application = body.application?.trim().toLowerCase() ?? null;

    if (!application) {
      throw new DemoAccessServiceError(
        "validation_error",
        "Application is required",
        400
      );
    }

    await logDemoTokenAccessEvent({
      contactId,
      email: body.email ?? null,
      name: body.name ?? null,
      designation: body.designation ?? null,
      companySize: body.companySize ?? null,
      branches: body.branches ?? null,
      ipAddress: body.ipAddress ?? null,
      userAgent: body.userAgent ?? null,
      application,
    });

    return res.status(204).end();
  } catch (error) {
    return handleServiceError(res, error);
  }
}
