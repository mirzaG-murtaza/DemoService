import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  DemoAccessServiceError,
  validateDemoToken,
} from "../../src/demoAccessService";
import { handleServiceError, readJsonBody } from "../../src/http";

type ValidateBody = {
  token?: string;
  enforceConversationLimit?: boolean;
  recordAccessTimestamp?: boolean;
  application?: string;
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
    const body = await readJsonBody<ValidateBody>(req);
    const token = body.token?.trim();

    if (!token) {
      throw new DemoAccessServiceError(
        "validation_error",
        "Token is required",
        400
      );
    }

    const application = body.application?.trim().toLowerCase();

    if (!application) {
      throw new DemoAccessServiceError(
        "validation_error",
        "Application is required",
        400
      );
    }

    const result = await validateDemoToken(token, {
      enforceConversationLimit:
        body.enforceConversationLimit !== undefined
          ? Boolean(body.enforceConversationLimit)
          : undefined,
      recordAccessTimestamp:
        body.recordAccessTimestamp !== undefined
          ? Boolean(body.recordAccessTimestamp)
          : undefined,
      application,
    });

    return res.status(200).json({ data: result });
  } catch (error) {
    return handleServiceError(res, error);
  }
}
