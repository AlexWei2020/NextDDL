import "server-only";
import { pool } from "@/lib/db";
import {
  decryptStoredPlatformDataForUser,
  encryptCredentialsPayloadForUser,
  StoredPlatformData,
} from "@/lib/credential-vault";
import { isSubmittedStatus } from "@/lib/deadline-status";
import fetchPlatform, {
  isPlatformSessionExpiredError,
  loginPlatformSession,
} from "@/lib/fetch-ddls";

type AuthMode = "session" | "credentials";
const SESSION_REFRESH_RETRY_COOLDOWN_MS = 15 * 60 * 1000;

type PlatformFetchResult = {
  platform: string;
  authMode: AuthMode;
  items: DeadlineItem[];
  expired: boolean;
  fetched: boolean;
  sessionRefreshed: boolean;
};

export type DeadlineItem = {
  platform: string;
  title: string;
  course: string;
  due: number;
  status?: string;
  url: string;
  completed?: boolean;
};

function toSessionPayload(data: Pick<StoredPlatformData, "cookies" | "url">) {
  return {
    session: data.cookies,
    ...(data.url ? { url: data.url } : {}),
  };
}

async function fetchPlatformDeadlines(
  userId: string,
  platform: string
): Promise<PlatformFetchResult> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    const rowResult = await client.query(
      `
      select id, encrypted_session, session_valid, session_checked_at
      from platform_sessions
      where user_id = $1 and platform = $2
      order by created_at desc
      limit 1
      for update
      `,
      [userId, platform]
    );

    if (rowResult.rows.length === 0) {
      await client.query("commit");
      return {
        platform,
        authMode: "session",
        items: [],
        expired: false,
        fetched: false,
        sessionRefreshed: false,
      };
    }

    const row = rowResult.rows[0];
    const stored = decryptStoredPlatformDataForUser(row.encrypted_session, userId);
    const authMode = stored.authMode;
    const lastCheckedAt = row.session_checked_at
      ? new Date(row.session_checked_at).getTime()
      : 0;
    const refreshRetryCoolingDown = row.session_valid === false
      && Number.isFinite(lastCheckedAt)
      && Date.now() - lastCheckedAt < SESSION_REFRESH_RETRY_COOLDOWN_MS;

    if (refreshRetryCoolingDown) {
      await client.query("commit");
      return {
        platform,
        authMode,
        items: [],
        expired: true,
        fetched: false,
        sessionRefreshed: false,
      };
    }

    if (stored.cookies && row.session_valid !== false) {
      try {
        const items = await fetchPlatform(platform, toSessionPayload(stored));
        await client.query(
          `update platform_sessions
           set session_valid = true, session_checked_at = now()
           where id = $1`,
          [row.id]
        );
        await client.query("commit");
        return {
          platform,
          authMode,
          items,
          expired: false,
          fetched: true,
          sessionRefreshed: false,
        };
      } catch (error) {
        if (!isPlatformSessionExpiredError(error)) {
          await client.query("commit");
          return {
            platform,
            authMode,
            items: [],
            expired: false,
            fetched: false,
            sessionRefreshed: false,
          };
        }
      }
    }

    if (authMode !== "credentials" || !stored.credentials) {
      await client.query(
        `update platform_sessions
         set session_valid = false, session_checked_at = now()
         where id = $1`,
        [row.id]
      );
      await client.query("commit");
      return {
        platform,
        authMode,
        items: [],
        expired: true,
        fetched: false,
        sessionRefreshed: false,
      };
    }

    try {
      const session = await loginPlatformSession(platform, stored.credentials);
      const items = await fetchPlatform(platform, toSessionPayload(session));
      const encrypted = encryptCredentialsPayloadForUser(
        userId,
        stored.credentials,
        session
      );
      await client.query(
        `update platform_sessions
         set encrypted_session = $1,
             session_valid = true,
             session_checked_at = now(),
             session_refreshed_at = now()
         where id = $2`,
        [encrypted, row.id]
      );
      await client.query("commit");
      return {
        platform,
        authMode,
        items,
        expired: false,
        fetched: true,
        sessionRefreshed: true,
      };
    } catch {
      await client.query(
        `update platform_sessions
         set session_valid = false, session_checked_at = now()
         where id = $1`,
        [row.id]
      );
      await client.query("commit");
      return {
        platform,
        authMode,
        items: [],
        expired: true,
        fetched: false,
        sessionRefreshed: false,
      };
    }
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export type RefreshResult = {
  items: DeadlineItem[];
  expiredPlatforms: string[];
  refreshedPlatforms: string[];
};

function getDeadlineKey(item: {
  platform?: string;
  title?: string;
  course?: string;
  due?: number;
  url?: string;
}) {
  return [
    item.platform ?? "",
    item.title ?? "",
    item.course ?? "",
    String(item.due ?? ""),
    item.url ?? "",
  ].join("|");
}

export async function refreshUserDeadlinesDetailed(userId: string): Promise<RefreshResult> {
  const retentionResult = await pool.query(
    `select ddl_retention_days from users where id = $1`,
    [userId]
  );
  const retentionValue = retentionResult.rows[0]?.ddl_retention_days;
  const retentionDays = Number.isFinite(Number(retentionValue)) && Number(retentionValue) > 0
    ? Number(retentionValue)
    : 30;

  const sessions = await pool.query(
    `
    select distinct platform
    from platform_sessions
    where user_id = $1
    order by platform
    `,
    [userId]
  );

  if (sessions.rows.length === 0) {
    return { items: [], expiredPlatforms: [], refreshedPlatforms: [] };
  }

  const results = await Promise.all(
    sessions.rows.map((row) => fetchPlatformDeadlines(userId, row.platform as string))
  );

  const expiredPlatforms = results
    .filter((result) => result.expired)
    .map((result) => result.platform);

  const refreshedPlatforms = results
    .filter((result) => result.sessionRefreshed)
    .map((result) => result.platform);

  const successfulResults = results.filter((result) => result.fetched);

  const items = successfulResults
    .flatMap((result) => result.items)
    .filter((item) => item && item.title && item.due)
    .filter((item) => {
      // keep items with due >= now - retentionDays
      const nowSec = Math.floor(Date.now() / 1000)
      const cutoff = nowSec - retentionDays * 24 * 60 * 60
      return Number(item.due) >= cutoff
    })

  const client = await pool.connect();
  try {
    await client.query("begin");
    const successfulPlatforms = successfulResults.map((result) => result.platform);
    const existingCompletedMap = new Map<string, boolean>();
    if (successfulPlatforms.length > 0) {
      const existingRows = await client.query(
        `
        select platform, title, course, extract(epoch from due_at)::bigint as due, url, completed
        from deadlines
        where user_id = $1 and platform = any($2::text[])
        `,
        [userId, successfulPlatforms]
      );

      for (const row of existingRows.rows) {
        const key = getDeadlineKey({
          platform: row.platform,
          title: row.title,
          course: row.course,
          due: Number(row.due),
          url: row.url,
        });
        existingCompletedMap.set(key, Boolean(row.completed));
      }

      await client.query(
        "delete from deadlines where user_id = $1 and platform = any($2::text[])",
        [userId, successfulPlatforms]
      );
    }

    for (const item of items) {
      const itemKey = getDeadlineKey(item);
      const completed = isSubmittedStatus(item.status)
        ? true
        : Boolean(item.completed) || Boolean(existingCompletedMap.get(itemKey));
      await client.query(
        `
        insert into deadlines (user_id, platform, title, course, due_at, status, completed, url)
        values ($1, $2, $3, $4, to_timestamp($5), $6, $7, $8)
        `,
        [
          userId,
          item.platform,
          item.title,
          item.course,
          item.due,
          item.status ?? null,
          completed,
          item.url,
        ]
      );
    }

    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }

  return { items, expiredPlatforms, refreshedPlatforms };
}

export async function refreshUserDeadlines(userId: string): Promise<DeadlineItem[]> {
  const result = await refreshUserDeadlinesDetailed(userId);
  return result.items;
}
