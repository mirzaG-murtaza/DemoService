# Demo Access Service

Self-contained Node service that manages demo-access tokens, email delivery, and Neon/Postgres persistence. It exposes lightweight HTTP endpoints so the main VoiceThru application (or any other client) can request, validate, and log usage of demo tokens over the network.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/demo/request` | Create a new demo token for a prospect |
| `POST` | `/api/demo/resend` | Re-issue the token email for an existing prospect |
| `POST` | `/api/demo/validate` | Validate a token and optionally update timestamps |
| `POST` | `/api/demo/conversation` | Increment the conversation counter for a token |
| `POST` | `/api/demo/log-access` | Record an access event for analytics/auditing |
| `GET` | `/api/invoiceextractor/access` | Evaluate invoice extraction allowance for an email |
| `GET` | `/api/health` | Basic health check |

All mutation endpoints accept JSON bodies and respond with JSON. Validation failures and domain errors use structured payloads containing `code`, `message`, and optional `details`.

Every mutating endpoint requires an `application` identifier that matches one of the entries in `ALLOWED_APPLICATIONS`. The service uses this value to stamp the `application` column, select the correct redirect URL, and reject cross-application access.

### Request Samples

```http
POST /api/demo/request
Content-Type: application/json

{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "designation": "CTO",
  "companySize": "50-200",
  "branches": "4",
  "application": "voicethru"
}
```

```http
POST /api/demo/validate
Content-Type: application/json

{
  "token": "token-from-email",
  "enforceConversationLimit": true,
  "recordAccessTimestamp": true,
  "application": "voicethru"
}
```

### Invoice Extractor Access

Use this lightweight guard from external workflows (e.g. n8n) to decide whether an invoice extraction run should proceed:

```http
GET /api/invoiceextractor/access?email=user@example.com
```

Successful responses always use HTTP 200 and include a payload describing the decision:

```json
{
  "data": {
    "allowed": true,
    "decision": "granted",
    "reason": "within_limit",
    "email": "user@example.com",
    "attemptCount": 2,
    "allowedAttempts": 3,
    "remainingAttempts": 1,
    "notificationEmailSent": false
  }
}
```

- When the usage limit has been exhausted, `allowed` becomes `false`, `decision` becomes `"denied"`, and the service sends a courtesy email to the requester (if SMTP credentials are configured) advising that no further invoice extraction is available.
- The allowance is driven by the shared `demo_constraints.conversations_allowed` value, so updating that table automatically adjusts both demo conversations and invoice extraction usage.

## Environment Variables

| Name | Purpose |
| --- | --- |
| `APP_BASE_URL` | Base URL used to craft demo links (defaults to `http://localhost:3000`) |
| `DEMO_CONVERSATION_LIMIT` | Maximum allowed conversations per token (`3` by default) |
| `DEMO_TOKEN_TTL_DAYS` | Number of days before a token expires (`7` by default) |
| `ALLOWED_APPLICATIONS` | Comma-separated list of permitted application identifiers |
| `APP_URL_<APPLICATION>` | Application-specific base URL (e.g. `APP_URL_VOICETHRU`, `APP_URL_INVOICEEXTRACTION`) |
| `EMAIL_FROM` / `NOREPLY_EMAIL_FROM` | Sender email address for outbound mail |
| `EMAIL_HOST` | SMTP host (`smtp.gmail.com` fallback) |
| `EMAIL_PORT` | SMTP port (`587` fallback) |
| `EMAIL_SECURE` | `"true"` to force TLS |
| `EMAIL_USER` / `SMTP_USER` | SMTP username |
| `EMAIL_PASSWORD` / `SMTP_PASSWORD` | SMTP password |
| `DEMO_DATABASE_URL` / `NEON_DATABASE_URL` / `DATABASE_URL` / `POSTGRES_URL` | Connection string for the Neon/Postgres demo database |

Set these in Vercel under **Project Settings -> Environment Variables** before deploying.

## Local Development

```bash
cp .env.example .env            # populate with real credentials
npm install
npm run build                   # type-check (tsc --noEmit)
vercel dev                      # run locally with Vercel CLI
```

`vercel dev` defaults to `http://localhost:3000`. Override with `--port` if needed.

## Deploying on Vercel

1. Create a new Vercel project and choose **Import Git Repository**.
2. Vercel detects the `api/` directory and provisions Node.js Serverless Functions automatically (thanks to `vercel.json`).
3. Configure the environment variables listed above for each environment (Production, Preview, Development).
4. Trigger the initial deployment. Once complete, note the base URL (e.g. `https://demo-access-service.vercel.app`). Each endpoint is available under this base (`/api/demo/request`, etc.).

## Integrating with the Main App

After deployment, point the main VoiceThru app to this service by setting `DEMO_SERVICE_URL` (e.g. `https://demo-access-service.vercel.app`) and using the wrappers in `services/demoAccessService.ts`:

```ts
await fetch(`${process.env.DEMO_SERVICE_URL}/api/demo/request`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload),
});
```

## Database Schema

In addition to the existing `demo_requests`, `demo_access_logs`, and `demo_constraints` tables, the invoice extractor workflow relies on the following table. Run the migration (or execute the SQL below) before deploying the new endpoint:

```sql
CREATE TABLE IF NOT EXISTS invoice_extractor_email_usage (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  application TEXT NOT NULL DEFAULT 'invoiceextractor',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  remaining_attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  limit_notified_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT invoice_extractor_email_usage_unique UNIQUE (email, application)
);

CREATE INDEX IF NOT EXISTS invoice_extractor_email_usage_email_idx
  ON invoice_extractor_email_usage (email);
```

This table stores a running counter of successful invoice extraction runs per email address. The endpoint only increments the counter when access is granted, ensuring the stored count mirrors actual usage.
`remaining_attempts` is recalculated from the shared `demo_constraints.conversations_allowed` limit so any updates to the constraint automatically flow through to future access decisions.

## Troubleshooting

- **Email not sending**: Ensure SMTP credentials are present. If omitted, the service will skip sending but still succeed, returning `emailSent: true` only when the transporter confirms delivery.
- **Database connectivity**: For Neon/Postgres, make sure Vercel's IP addresses are allowed or that the connection string enables pooled connections.
