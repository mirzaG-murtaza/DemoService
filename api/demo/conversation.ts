import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  DemoAccessServiceError,
  incrementDemoConversation,
} from "../../src/demoAccessService";
import { handleServiceError, readJsonBody } from "../../src/http";

type ConversationBody = {
  token?: string;
  requestedCount?: number;
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
    const body = await readJsonBody<ConversationBody>(req);
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

    const result = await incrementDemoConversation(
      token,
      body.requestedCount ?? undefined,
      application
    );

    return res.status(200).json({ data: result });
  } catch (error) {
    return handleServiceError(res, error);
  }
}
