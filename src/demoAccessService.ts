import { v4 as uuidv4 } from "uuid";
import nodemailer from "nodemailer";
import {
  saveDemoRequestToPostgres,
  markDemoRequestAccess,
  getDemoRequestByToken,
  getDemoRequestByEmail,
  updateDemoRequestProfile,
  insertDemoAccessLogEntry,
  type DemoRequestRow,
} from "./lib/demo-db";

const DEMO_CONVERSATION_LIMIT = Number(
  process.env.DEMO_CONVERSATION_LIMIT ||
    process.env.NEXT_PUBLIC_DEMO_CONVERSATION_LIMIT ||
    "3"
);

const DEMO_TOKEN_TTL_DAYS = Number(
  process.env.DEMO_TOKEN_TTL_DAYS ||
    process.env.NEXT_PUBLIC_DEMO_TOKEN_TTL_DAYS ||
    "7"
);

const APP_BASE_URL =
  process.env.APP_BASE_URL ||
  process.env.NEXT_PUBLIC_APP_URL ||
  "http://localhost:3000";

const EMAIL_FROM =
  process.env.EMAIL_FROM || process.env.NOREPLY_EMAIL_FROM || "noreply@voicethru.com";

const ALLOWED_APPLICATIONS = (
  process.env.ALLOWED_APPLICATIONS || "voicethru"
)
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

const APPLICATION_LABELS: Record<string, string> = {
  voicethru: "VoiceThru",
  invoiceextraction: "Invoice Extraction",
};

const DEFAULT_APPLICATION = ALLOWED_APPLICATIONS[0] || "voicethru";

function normalizeApplication(input?: string | null): string {
  const trimmed = (input ?? "").trim().toLowerCase();
  const value = trimmed || DEFAULT_APPLICATION;

  if (ALLOWED_APPLICATIONS.length > 0 && !ALLOWED_APPLICATIONS.includes(value)) {
    throw new DemoAccessServiceError(
      "invalid_application",
      `Unsupported application identifier: ${input}`,
      400
    );
  }

  return value;
}

function resolveApplicationEnvKey(application: string): string {
  return `APP_URL_${application.replace(/[^a-z0-9]/gi, "_").toUpperCase()}`;
}

function resolveApplicationBaseUrl(application: string): string {
  const envKey = resolveApplicationEnvKey(application);
  const value =
    process.env[envKey as keyof NodeJS.ProcessEnv] ??
    process.env[envKey.toLowerCase() as keyof NodeJS.ProcessEnv];

  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }

  return APP_BASE_URL;
}

function getApplicationLabel(application: string): string {
  return APPLICATION_LABELS[application] || application;
}

export class DemoAccessServiceError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number = 400,
    public details?: Record<string, unknown>
  ) {
    super(message);
  }
}

export interface DemoRequestPayload {
  name: string;
  email: string;
  designation: string;
  companySize: string;
  branches: string;
  application: string;
}

export interface DemoLinkResult {
  token: string;
  expiresAt: Date;
  emailSent: boolean;
  supabaseId: number | null;
  neonId: number;
  application: string;
}

export interface DemoTokenValidationResult {
  demoRequest: DemoRequestRow;
  expiresAt: Date;
  conversationCount: number;
  conversationLimit: number;
  application: string;
}

function generateDemoToken(): string {
  return uuidv4();
}

function calculateExpiryDate(from = new Date()): Date {
  const expiry = new Date(from);
  expiry.setDate(expiry.getDate() + DEMO_TOKEN_TTL_DAYS);
  return expiry;
}

function buildDemoLink(token: string, application: string) {
  const baseUrl = resolveApplicationBaseUrl(application);

  try {
    const url = new URL(baseUrl);
    url.pathname = url.pathname.replace(/\/?$/, "/demo");
    url.searchParams.set("token", token);
    return url.toString();
  } catch (error) {
    console.warn(
      "[DemoAccessService] Failed to construct URL using base",
      baseUrl,
      error
    );
    return `${baseUrl.replace(/\/$/, "")}/demo?token=${encodeURIComponent(token)}`;
  }
}

function createEmailTransporter(): nodemailer.Transporter | null {
  const emailUser = process.env.EMAIL_USER || process.env.SMTP_USER;
  const emailPassword = process.env.EMAIL_PASSWORD || process.env.SMTP_PASSWORD;

  if (!emailUser || !emailPassword) {
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST || "smtp.gmail.com",
    port: Number(process.env.EMAIL_PORT || 587),
    secure: process.env.EMAIL_SECURE === "true",
    auth: {
      user: emailUser,
      pass: emailPassword,
    },
    debug: process.env.NODE_ENV !== "production",
    logger: process.env.NODE_ENV !== "production",
  });
}

async function sendDemoAccessEmail(
  fullName: string,
  recipient: string,
  token: string,
  application: string
): Promise<boolean> {
  try {
    const transporter = createEmailTransporter();
    if (!transporter) {
      console.warn(
        "[DemoAccessService] Email transporter not configured; skipping email send."
      );
      return true;
    }

    const applicationLabel = getApplicationLabel(application);
    const link = buildDemoLink(token, application);
    const mailOptions = {
      from: EMAIL_FROM,
      to: recipient,
      subject: `Your ${applicationLabel} Demo Access Link`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Your ${applicationLabel} demo link is ready</h2>
          <p>Hello ${fullName || "there"},</p>
          <p>Use the link below to access your ${applicationLabel} demo. This link expires in ${DEMO_TOKEN_TTL_DAYS} days.</p>
          <p><a href="${link}" style="display: inline-block; background-color: #4F46E5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Launch Demo</a></p>
          <p>If you did not request this link, please ignore this email.</p>
          <p>Thanks,<br>The ${applicationLabel} Team</p>
        </div>
      `,
    };

    await transporter.verify();
    const info = await transporter.sendMail(mailOptions);
    console.log("[DemoAccessService] Demo access email sent", {
      messageId: info.messageId,
      preview: nodemailer.getTestMessageUrl(info),
    });
    return true;
  } catch (error) {
    console.error("[DemoAccessService] Failed to send demo email:", error);
    return false;
  }
}

async function sendDemoDuplicateNoticeEmail(
  fullName: string,
  recipient: string,
  application: string
): Promise<boolean> {
  const transporter = createEmailTransporter();

  if (!transporter) {
    console.warn(
      "[DemoAccessService] Email transporter not configured; skipping duplicate request notification."
    );
    return true;
  }

  const applicationLabel = getApplicationLabel(application);
  const safeName = fullName || "there";

  const mailOptions = {
    from: EMAIL_FROM,
    to: recipient,
    subject: `${applicationLabel} Demo Already Used`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>${applicationLabel} Demo Already Used</h2>
        <p>Hello ${safeName},</p>
        <p>Thanks for your interest in the ${applicationLabel} experience. Our records show that this email address has already used the demo for this application.</p>
        <p>Please contact the BTL Admin for a full tour of our application and to discuss next steps.</p>
        <p>We look forward to guiding you through everything ${applicationLabel} has to offer.</p>
        <p>Warm regards,<br/>The VoiceThru Team</p>
      </div>
    `,
  };

  try {
    await transporter.verify();
    const info = await transporter.sendMail(mailOptions);
    console.log("[DemoAccessService] Duplicate demo notification email sent", {
      messageId: info.messageId,
      preview: nodemailer.getTestMessageUrl(info),
    });
    return true;
  } catch (error) {
    console.error(
      "[DemoAccessService] Failed to send duplicate demo notification email:",
      error
    );
    return false;
  }
}

async function issueDemoAccessLink(
  payload: DemoRequestPayload
): Promise<DemoLinkResult> {
  const token = generateDemoToken();
  const issuedAt = new Date();
  const expiresAt = calculateExpiryDate(issuedAt);
  const application = normalizeApplication(payload.application);

  const neonRecord = await saveDemoRequestToPostgres({
    fullName: payload.name,
    email: payload.email,
    designation: payload.designation,
    companySize: payload.companySize,
    numberOfBranches: payload.branches,
    application,
    accessToken: token,
    accessExpiry: expiresAt,
    hasAccess: true,
    conversationCount: DEMO_CONVERSATION_LIMIT,
  });

  const emailSent = await sendDemoAccessEmail(
    payload.name,
    payload.email,
    token,
    application
  );

  if (emailSent) {
    await markDemoRequestAccess(neonRecord.id, {
      tokenSentAt: issuedAt,
    });
  }

  return {
    token,
    expiresAt,
    emailSent,
    supabaseId: null,
    neonId: neonRecord.id,
    application,
  };
}

export async function submitDemoRequest(
  payload: DemoRequestPayload
): Promise<DemoLinkResult> {
  const application = normalizeApplication(payload.application);
  const existing = await getDemoRequestByEmail(payload.email);

  if (existing) {
    const recordApplication = existing.application
      ? normalizeApplication(existing.application)
      : application;

    if (recordApplication === application) {
      await updateDemoRequestProfile(existing.id, {
        fullName: payload.name,
        designation: payload.designation,
        companySize: payload.companySize,
        numberOfBranches: payload.branches,
      });

      const emailSent = await sendDemoDuplicateNoticeEmail(
        payload.name,
        payload.email,
        application
      );

      let expiresAt = existing.access_expiry
        ? new Date(existing.access_expiry)
        : null;
      if (!expiresAt || Number.isNaN(expiresAt.getTime())) {
        expiresAt = calculateExpiryDate();
      }

      return {
        token: existing.access_token ?? "",
        expiresAt,
        emailSent,
        supabaseId: null,
        neonId: existing.id,
        application,
      };
    }
  }

  return issueDemoAccessLink({ ...payload, application });
}

export async function resendDemoAccessLink(
  email: string,
  application?: string
): Promise<DemoLinkResult> {
  if (!application) {
    throw new DemoAccessServiceError(
      "application_required",
      "Application is required",
      400
    );
  }

  const existing = await getDemoRequestByEmail(email);
  if (!existing) {
    throw new DemoAccessServiceError(
      "not_found",
      "Demo request not found for this email",
      404
    );
  }

  const requestedApplication = normalizeApplication(application);
  const recordApplication = normalizeApplication(existing.application);
  if (requestedApplication !== recordApplication) {
    throw new DemoAccessServiceError(
      "application_mismatch",
      "Email belongs to a different application",
      403
    );
  }

  return issueDemoAccessLink({
    name: existing.full_name || "Guest",
    email: existing.email,
    designation: existing.designation || "Unknown",
    companySize: existing.company_size || "Unknown",
    branches: existing.number_of_branches || "Unknown",
    application: recordApplication,
  });
}

interface ValidateOptions {
  enforceConversationLimit?: boolean;
  recordAccessTimestamp?: boolean;
  application?: string;
}

async function fetchDemoRequestOrThrow(
  token: string,
  expectedApplication?: string
): Promise<DemoRequestRow> {
  if (!token) {
    throw new DemoAccessServiceError("token_required", "Token is required", 400);
  }

  const demoRequest = await getDemoRequestByToken(token);
  if (!demoRequest) {
    throw new DemoAccessServiceError("not_found", "Invalid token", 404);
  }

  if (demoRequest.has_access === false) {
    throw new DemoAccessServiceError(
      "access_pending",
      "Access not granted yet",
      403
    );
  }

  if (expectedApplication) {
    const normalizedExpected = normalizeApplication(expectedApplication);
    const recordApplication = normalizeApplication(demoRequest.application);
    if (normalizedExpected !== recordApplication) {
      throw new DemoAccessServiceError(
        "application_mismatch",
        "Token does not belong to this application",
        403,
        {
          expectedApplication: normalizedExpected,
          tokenApplication: recordApplication,
        }
      );
    }
  }

  return demoRequest;
}

export async function validateDemoToken(
  token: string,
  options: ValidateOptions = {}
): Promise<DemoTokenValidationResult> {
  const {
    enforceConversationLimit = true,
    recordAccessTimestamp = true,
  } = options;

  const application = options.application
    ? normalizeApplication(options.application)
    : null;

  if (!application) {
    throw new DemoAccessServiceError(
      "application_required",
      "Application is required",
      400
    );
  }

  const demoRequest = await fetchDemoRequestOrThrow(token, application);

  const now = new Date();
  const expiryDate = demoRequest.access_expiry
    ? new Date(demoRequest.access_expiry)
    : null;

  if (!expiryDate || now > expiryDate) {
    throw new DemoAccessServiceError("expired", "Token has expired", 403);
  }

  const remainingConversations =
    demoRequest.conversation_count ?? DEMO_CONVERSATION_LIMIT;
  const usedConversations = Math.max(
    DEMO_CONVERSATION_LIMIT - remainingConversations,
    0
  );

  if (enforceConversationLimit && remainingConversations <= 0) {
    try {
      await markDemoRequestAccess(demoRequest.id, {
        hasAccess: false,
        conversationCount: 0,
      });
    } catch (error) {
      console.warn(
        "[DemoAccessService] Failed to disable access during limit validation:",
        error
      );
    }

    throw new DemoAccessServiceError(
      "limit_reached",
      "Conversation limit reached",
      403,
      {
        conversationCount: usedConversations,
        conversationLimit: DEMO_CONVERSATION_LIMIT,
      }
    );
  }

  if (recordAccessTimestamp) {
    await markDemoRequestAccess(demoRequest.id, {
      lastAccessedAt: now,
      tokenUsedAt: now,
    });
  }

  return {
    demoRequest,
    expiresAt: expiryDate,
    conversationCount: usedConversations,
    conversationLimit: DEMO_CONVERSATION_LIMIT,
    application,
  };
}

export async function incrementDemoConversation(
  token: string,
  requestedCount?: number,
  application?: string
): Promise<{ conversationCount: number; conversationLimit: number }> {
  const normalizedApplication = application
    ? normalizeApplication(application)
    : null;

  if (!normalizedApplication) {
    throw new DemoAccessServiceError(
      "application_required",
      "Application is required",
      400
    );
  }

  const demoRequest = await fetchDemoRequestOrThrow(
    token,
    normalizedApplication
  );
  const remainingConversations =
    demoRequest.conversation_count ?? DEMO_CONVERSATION_LIMIT;
  const usedConversations = Math.max(
    DEMO_CONVERSATION_LIMIT - remainingConversations,
    0
  );
  const minimumNextUsed = usedConversations + 1;

  const requestedUsedCount =
    typeof requestedCount === "number" && Number.isFinite(requestedCount)
      ? Math.max(requestedCount, minimumNextUsed)
      : minimumNextUsed;
  const nextUsedCount = requestedUsedCount;

  if (nextUsedCount > DEMO_CONVERSATION_LIMIT) {
    try {
      await markDemoRequestAccess(demoRequest.id, {
        hasAccess: false,
        conversationCount: 0,
      });
    } catch (error) {
      console.warn(
        "[DemoAccessService] Failed to disable access after exceeding conversation limit:",
        error
      );
    }

    throw new DemoAccessServiceError(
      "limit_reached",
      "Conversation limit reached",
      403,
      {
        conversationCount: usedConversations,
        conversationLimit: DEMO_CONVERSATION_LIMIT,
      }
    );
  }

  const nextRemainingCount = Math.max(
    DEMO_CONVERSATION_LIMIT - nextUsedCount,
    0
  );

  try {
    await markDemoRequestAccess(demoRequest.id, {
      conversationCount: nextRemainingCount,
      lastConversationAt: new Date(),
      hasAccess: nextRemainingCount > 0,
    });
  } catch (error) {
    console.warn(
      "[DemoAccessService] Failed to update conversation count in demo_requests:",
      error
    );
  }

  return {
    conversationCount: nextUsedCount,
    conversationLimit: DEMO_CONVERSATION_LIMIT,
  };
}

export async function logDemoTokenAccessEvent(params: {
  contactId: string;
  email?: string | null;
  name?: string | null;
  designation?: string | null;
  companySize?: string | null;
  branches?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  application?: string | null;
}): Promise<void> {
  const {
    contactId,
    email,
    name,
    designation,
    companySize,
    branches,
    ipAddress,
    userAgent,
    application,
  } = params;

  if (!contactId) {
    throw new DemoAccessServiceError(
      "contact_required",
      "Contact identifier is required",
      400
    );
  }

  if (!application) {
    throw new DemoAccessServiceError(
      "application_required",
      "Application is required",
      400
    );
  }

  const requestedApplication = normalizeApplication(application);

  try {
    const now = new Date();
    const existing = await getDemoRequestByToken(contactId);

    let demoRequestId: number;

    if (existing) {
      const recordApplication = existing.application
        ? normalizeApplication(existing.application)
        : requestedApplication;

      if (requestedApplication !== recordApplication) {
        throw new DemoAccessServiceError(
          "application_mismatch",
          "Contact belongs to a different application",
          403
        );
      }

      await updateDemoRequestProfile(existing.id, {
        fullName: name ?? undefined,
        email: email ?? undefined,
        designation: designation ?? undefined,
        companySize: companySize ?? undefined,
        numberOfBranches: branches ?? undefined,
        lastAccessedAt: now,
      });

      demoRequestId = existing.id;
    } else {
      const saveResult = await saveDemoRequestToPostgres({
        fullName: name || "Unknown User",
        email: email || "unknown@example.com",
        designation: designation || "Unknown",
        companySize: companySize || "Unknown",
        numberOfBranches: branches || "Unknown",
        application: requestedApplication,
        accessToken: contactId,
        accessExpiry: calculateExpiryDate().toISOString(),
        hasAccess: true,
        lastAccessedAt: now,
      });

      demoRequestId = saveResult.id;
    }

    await insertDemoAccessLogEntry({
      demoRequestId,
      ipAddress: ipAddress || "Unknown",
      userAgent: userAgent || "Unknown",
      accessedAt: now,
    });
  } catch (error) {
    console.error("[DemoAccessService] Failed to log demo access event:", error);
    throw new DemoAccessServiceError(
      "log_failed",
      "Failed to log demo access event",
      500
    );
  }
}
