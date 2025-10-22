import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  DemoAccessServiceError,
  resendDemoAccessLink,
} from "../../src/demoAccessService";
import { handleServiceError, readJsonBody } from "../../src/http";

type ResendBody = {
  email?: string;
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
    const body = await readJsonBody<ResendBody>(req);
    const email = body.email?.trim();

    if (!email) {
      throw new DemoAccessServiceError(
        "validation_error",
        "Email is required",
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

    const result = await resendDemoAccessLink(email, application);
    return res.status(200).json({ data: result });
  } catch (error) {
    return handleServiceError(res, error);
  }
}
