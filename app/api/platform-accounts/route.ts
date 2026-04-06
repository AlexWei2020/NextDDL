import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { pool } from "@/lib/db";
import {
  detectStoredAuthMode,
  encryptCredentialsPayloadForUser,
  encryptSessionPayload,
} from "@/lib/credential-vault";

type Fields = Record<string, string>;
type AuthMode = "session" | "credentials";
type SaveItem ={
    platform: string;
    identifierField?: string;
    fields: Fields;
  authMode?: AuthMode;
}

const PLATFORM_API: Record<string, string> = {
  Hydro: "/api/hydro",
  Gradescope: "/api/gradescope",
  Blackboard: "/api/blackboard",
};

const PLATFORM_REQUIRED_FIELDS: Record<string, string[]> = {
  Hydro: ["url", "username", "password"],
  Gradescope: ["email", "password"],
  Blackboard: ["studentid", "password"],
};

function getPythonBaseUrl() {
  const base = process.env.PYTHON_API_BASE_URL ||
    (process.env.NODE_ENV === "development" ? "http://127.0.0.1:5000" : "");
  if (!base) {
    throw new Error("Missing PYTHON_API_BASE_URL");
  }
  return base;
}

export async function GET(){
    const user = await getCurrentUser();
    if (!user) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const result = await pool.query(
        `
        select distinct on (platform) platform, encrypted_session
        from platform_sessions
        where user_id = $1
        order by platform, created_at desc
        `,
        [user.id]
    )
    const items = result.rows.map((row) => {
        try {
          const authMode = detectStoredAuthMode(row.encrypted_session)
          return { platform: row.platform, configured: true, authMode }
        } catch (error) {
          return { platform: row.platform, configured: false, authMode: "session" }
        }
    })
    return NextResponse.json({ items })
}

export async function POST(request: Request) {
  const user = await getCurrentUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const body = await request.json()
  const items: SaveItem[] = body.items ?? []

  const client = await pool.connect()
  try {
    await client.query('begin')

    for (const item of items) {
      const fields = item.fields ?? {}
      const authMode: AuthMode = item.authMode === "credentials" ? "credentials" : "session"
      const api = PLATFORM_API[item.platform]
      const requiredFields = PLATFORM_REQUIRED_FIELDS[item.platform] ?? []
      if (!api) {
        throw new Error(`Unsupported platform: ${item.platform}`)
      }
      if (!requiredFields.every((key) => Boolean(fields[key]))) {
        throw new Error(`Missing required fields for ${item.platform}`)
      }

      const baseUrl = getPythonBaseUrl()
      const payload = authMode === "session"
        ? { ...fields, include_session: true }
        : { ...fields }
      const response = await fetch(`${baseUrl}${api}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        throw new Error(`Failed to validate ${item.platform} account`)
      }
      const result = await response.json()
      if (result?.status !== "success") {
        throw new Error(`Failed to validate ${item.platform} account`)
      }

      let storedData: Record<string, unknown> = {}
      let sessionValid: boolean | null
      let sessionCheckedAtSql = "now()"

      if (authMode === "session") {
        if (!result?.session) {
          throw new Error(`Failed to fetch session for ${item.platform}`)
        }
        storedData = item.platform === "Hydro"
          ? { authMode, cookies: result.session, url: fields.url }
          : { authMode, cookies: result.session }
        sessionValid = true
      } else {
        sessionValid = null
        sessionCheckedAtSql = "null"
      }

      await client.query(
        `delete from platform_sessions where user_id = $1 and platform = $2`,
        [user.id, item.platform]
      )

      const encrypted = authMode === "credentials"
        ? encryptCredentialsPayloadForUser(user.id, fields)
        : encryptSessionPayload(storedData)
      await client.query(
        `
        insert into platform_sessions (user_id, platform, encrypted_session, expires_at, session_valid, session_checked_at)
        values ($1, $2, $3, null, $4, ${sessionCheckedAtSql})
        `,
        [user.id, item.platform, encrypted, sessionValid]
      )
    }

    await client.query('commit')
    return NextResponse.json({ ok: true })
  } catch (error) {
    await client.query('rollback')
    console.error(error)
    return NextResponse.json({ error: 'Failed to save' }, { status: 500 })
  } finally {
    client.release()
  }
}