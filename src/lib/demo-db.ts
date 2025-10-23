import { Pool } from 'pg';

const connectionString =
  process.env.DEMO_DATABASE_URL ||
  process.env.NEON_DATABASE_URL ||
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL;

const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
    })
  : null;

function requirePool() {
  if (!pool) {
    throw new Error('Demo database connection is not configured.');
  }
  return pool;
}

export type DemoConstraintsRow = {
  id: number;
  conversation_timer_seconds: number | null;
  conversations_allowed: number | null;
  token_expiry_seconds: number | null;
};

export async function getDemoConstraints(): Promise<DemoConstraintsRow | null> {
  const activePool = requirePool();
  const client = await activePool.connect();

  try {
    const result = await client.query<DemoConstraintsRow>(
      `
        SELECT
          id,
          EXTRACT(EPOCH FROM conversation_timer) AS conversation_timer_seconds,
          conversations_allowed,
          EXTRACT(EPOCH FROM token_expiry) AS token_expiry_seconds
        FROM demo_constraints
        ORDER BY id ASC
        LIMIT 1
      `,
    );
    return result.rows[0] ?? null;
  } catch (error) {
    if ((error as { code?: string })?.code === '42P01') {
      console.warn('[DemoAccessService] demo_constraints table not found; falling back to defaults.');
      return null;
    }
    throw error;
  } finally {
    client.release();
  }
}

export type DemoRequestRecord = {
  fullName: string;
  email: string;
  designation: string;
  companySize: string;
  numberOfBranches: string;
  application?: string;
  accessToken?: string;
  accessExpiry?: Date | string;
  hasAccess?: boolean;
  tokenSentAt?: Date | string;
  tokenUsedAt?: Date | string | null;
  lastAccessedAt?: Date | string | null;
  conversationCount?: number;
  lastConversationAt?: Date | string | null;
};

export type DemoRequestPersistenceResult = {
  id: number;
  action: 'inserted' | 'updated';
};

export type DemoRequestRow = {
  id: number;
  full_name: string;
  email: string;
  designation: string;
  company_size: string;
  number_of_branches: string;
  application: string | null;
  has_access: boolean;
  created_at: string;
  access_token: string | null;
  access_expiry: string | null;
  last_accessed_at: string | null;
  token_sent_at: string | null;
  token_used_at: string | null;
  conversation_count: number | null;
  last_conversation_at: string | null;
};

export async function saveDemoRequestToPostgres(
  payload: DemoRequestRecord,
): Promise<DemoRequestPersistenceResult> {
  const activePool = requirePool();
  const client = await activePool.connect();

  const {
    fullName,
    email,
    designation,
    companySize,
    numberOfBranches,
    application = 'voicethru',
    accessToken,
    accessExpiry,
    hasAccess = true,
    tokenSentAt,
    tokenUsedAt,
    lastAccessedAt,
    conversationCount,
    lastConversationAt,
  } = payload;

  const normalizedExpiry =
    accessExpiry instanceof Date ? accessExpiry.toISOString() : accessExpiry;
  const normalizedTokenSentAt =
    tokenSentAt instanceof Date ? tokenSentAt.toISOString() : tokenSentAt;
  const normalizedTokenUsedAt =
    tokenUsedAt instanceof Date ? tokenUsedAt.toISOString() : tokenUsedAt;
  const normalizedLastAccessed =
    lastAccessedAt instanceof Date
      ? lastAccessedAt.toISOString()
      : lastAccessedAt;
  const normalizedLastConversation =
    lastConversationAt instanceof Date
      ? lastConversationAt.toISOString()
      : lastConversationAt;

  try {
    const existing = await client.query<{ id: number }>(
      'SELECT id FROM demo_requests WHERE LOWER(email) = LOWER($1) LIMIT 1',
      [email],
    );

    if (existing.rows.length > 0) {
      await client.query(
        `UPDATE demo_requests
         SET full_name = $1,
             designation = $2,
             company_size = $3,
             number_of_branches = $4,
             application = $5,
             has_access = $6,
             access_token = COALESCE($7, access_token),
             access_expiry = COALESCE($8, access_expiry),
             token_sent_at = COALESCE($9, token_sent_at),
             token_used_at = COALESCE($10, token_used_at),
             last_accessed_at = COALESCE($11, last_accessed_at),
             conversation_count = COALESCE($12, conversation_count),
             last_conversation_at = COALESCE($13, last_conversation_at)
         WHERE id = $14`,
        [
          fullName,
          designation,
          companySize,
          numberOfBranches,
          application,
          hasAccess,
          accessToken ?? null,
          normalizedExpiry ?? null,
          normalizedTokenSentAt ?? null,
          normalizedTokenUsedAt ?? null,
          normalizedLastAccessed ?? null,
          conversationCount ?? null,
          normalizedLastConversation ?? null,
          existing.rows[0].id,
        ],
      );

      return { id: existing.rows[0].id, action: 'updated' };
    }

    const inserted = await client.query<{ id: number }>(
      `INSERT INTO demo_requests (
        full_name,
        email,
        designation,
        company_size,
        number_of_branches,
        application,
        has_access,
        access_token,
        access_expiry,
        token_sent_at,
        token_used_at,
        last_accessed_at,
        conversation_count,
        last_conversation_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING id`,
      [
        fullName,
        email,
        designation,
        companySize,
        numberOfBranches,
        application,
        hasAccess,
        accessToken ?? null,
        normalizedExpiry ?? null,
        normalizedTokenSentAt ?? null,
        normalizedTokenUsedAt ?? null,
        normalizedLastAccessed ?? null,
        conversationCount ?? 0,
        normalizedLastConversation ?? null,
      ],
    );

    return { id: inserted.rows[0].id, action: 'inserted' };
  } finally {
    client.release();
  }
}

export async function getDemoRequestByToken(
  token: string,
): Promise<DemoRequestRow | null> {
  const activePool = requirePool();
  const client = await activePool.connect();

  try {
    const result = await client.query<DemoRequestRow>(
      'SELECT * FROM demo_requests WHERE access_token = $1 LIMIT 1',
      [token],
    );
    return result.rows[0] ?? null;
  } finally {
    client.release();
  }
}

export async function getDemoRequestByEmail(
  email: string,
): Promise<DemoRequestRow | null> {
  const activePool = requirePool();
  const client = await activePool.connect();

  try {
    const result = await client.query<DemoRequestRow>(
      'SELECT * FROM demo_requests WHERE LOWER(email) = LOWER($1) LIMIT 1',
      [email],
    );
    return result.rows[0] ?? null;
  } finally {
    client.release();
  }
}

export async function markDemoRequestAccess(
  id: number,
  updates: Partial<Pick<DemoRequestRecord, 'accessToken' | 'accessExpiry' | 'tokenSentAt' | 'tokenUsedAt' | 'lastAccessedAt' | 'hasAccess' | 'conversationCount' | 'lastConversationAt'>>,
) {
  const activePool = requirePool();
  const client = await activePool.connect();

  const fields: string[] = [];
  const values: any[] = [];

  const pushField = (column: string, value: unknown) => {
    fields.push(`${column} = $${fields.length + 1}`);
    values.push(value);
  };

  if (Object.prototype.hasOwnProperty.call(updates, 'accessToken')) {
    pushField('access_token', updates.accessToken ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'accessExpiry')) {
    const expiry =
      updates.accessExpiry instanceof Date
        ? updates.accessExpiry.toISOString()
        : updates.accessExpiry ?? null;
    pushField('access_expiry', expiry);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'tokenSentAt')) {
    const ts =
      updates.tokenSentAt instanceof Date
        ? updates.tokenSentAt.toISOString()
        : updates.tokenSentAt ?? null;
    pushField('token_sent_at', ts);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'tokenUsedAt')) {
    const used =
      updates.tokenUsedAt instanceof Date
        ? updates.tokenUsedAt.toISOString()
        : updates.tokenUsedAt ?? null;
    pushField('token_used_at', used);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'lastAccessedAt')) {
    const last =
      updates.lastAccessedAt instanceof Date
        ? updates.lastAccessedAt.toISOString()
        : updates.lastAccessedAt ?? null;
    pushField('last_accessed_at', last);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'conversationCount')) {
    pushField('conversation_count', updates.conversationCount ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'lastConversationAt')) {
    const lastConv =
      updates.lastConversationAt instanceof Date
        ? updates.lastConversationAt.toISOString()
        : updates.lastConversationAt ?? null;
    pushField('last_conversation_at', lastConv);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'hasAccess')) {
    pushField('has_access', updates.hasAccess ?? null);
  }

  if (fields.length === 0) {
    client.release();
    return;
  }

  values.push(id);

  try {
    await client.query(
      `UPDATE demo_requests
       SET ${fields.join(', ')}
       WHERE id = $${fields.length + 1}`,
      values,
    );
  } finally {
    client.release();
  }
}

export async function updateDemoRequestProfile(
  id: number,
  updates: {
    fullName?: string | null;
    email?: string | null;
    designation?: string | null;
    companySize?: string | null;
    numberOfBranches?: string | null;
    lastAccessedAt?: Date | string | null;
  },
) {
  const activePool = requirePool();
  const client = await activePool.connect();

  const fields: string[] = [];
  const values: any[] = [];

  const pushField = (column: string, value: unknown) => {
    fields.push(`${column} = $${fields.length + 1}`);
    values.push(value);
  };

  if (Object.prototype.hasOwnProperty.call(updates, 'fullName')) {
    pushField('full_name', updates.fullName ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'email')) {
    pushField('email', updates.email ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'designation')) {
    pushField('designation', updates.designation ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'companySize')) {
    pushField('company_size', updates.companySize ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'numberOfBranches')) {
    pushField('number_of_branches', updates.numberOfBranches ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'lastAccessedAt')) {
    const last =
      updates.lastAccessedAt instanceof Date
        ? updates.lastAccessedAt.toISOString()
        : updates.lastAccessedAt ?? null;
    pushField('last_accessed_at', last);
  }

  if (fields.length === 0) {
    client.release();
    return;
  }

  values.push(id);

  try {
    await client.query(
      `UPDATE demo_requests
       SET ${fields.join(', ')}
       WHERE id = $${fields.length + 1}`,
      values,
    );
  } finally {
    client.release();
  }
}

export async function insertDemoAccessLogEntry(payload: {
  demoRequestId: number;
  ipAddress?: string | null;
  userAgent?: string | null;
  accessedAt?: Date | string;
}) {
  const activePool = requirePool();
  const client = await activePool.connect();

  const accessedAt =
    payload.accessedAt instanceof Date
      ? payload.accessedAt.toISOString()
      : payload.accessedAt ?? new Date().toISOString();

  try {
    await client.query(
      `INSERT INTO demo_access_logs
         (demo_request_id, ip_address, user_agent, accessed_at)
       VALUES ($1, $2, $3, $4)`,
      [
        payload.demoRequestId,
        payload.ipAddress ?? null,
        payload.userAgent ?? null,
        accessedAt,
      ],
    );
  } finally {
    client.release();
  }
}
