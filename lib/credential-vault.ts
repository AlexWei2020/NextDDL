import "server-only";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  constants,
} from "crypto";
import { decryptJson, encryptJson } from "@/lib/crypto";

type AuthMode = "session" | "credentials";
type Fields = Record<string, string>;

export type StoredPlatformSession = {
  cookies: Record<string, string>;
  url?: string;
};

export type StoredPlatformData = {
  authMode: AuthMode;
  credentials?: Fields;
  cookies?: Record<string, string>;
  url?: string;
};

type CredentialEntry = {
  wrappedKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

type CredentialEnvelopeV1 = {
  format: "rsa-aes-v1";
  authMode: "credentials";
  userHashSalt: string;
  credentialsByUserHash: Record<string, CredentialEntry>;
  createdAt: string;
};

type CredentialEnvelopeV2 = Omit<CredentialEnvelopeV1, "format"> & {
  format: "rsa-aes-v2";
};

type StoredCredentialsV2 = {
  credentials: Fields;
  session?: StoredPlatformSession;
};

function normalizePem(raw: string | undefined) {
  if (!raw) return "";
  return raw.includes("\\n") ? raw.replace(/\\n/g, "\n") : raw;
}

function getPublicKey() {
  const key = normalizePem(process.env.PLATFORM_RSA_PUBLIC_KEY);
  if (!key) {
    throw new Error("Missing PLATFORM_RSA_PUBLIC_KEY");
  }
  return key;
}

function getPrivateKey() {
  const key = normalizePem(process.env.PLATFORM_RSA_PRIVATE_KEY);
  if (!key) {
    throw new Error("Missing PLATFORM_RSA_PRIVATE_KEY");
  }
  return key;
}

function hashUserId(userId: string, saltB64: string) {
  return createHash("sha256").update(`${saltB64}:${userId}`).digest("hex");
}

function isCredentialEnvelope(value: unknown): value is CredentialEnvelopeV1 | CredentialEnvelopeV2 {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return (obj.format === "rsa-aes-v1" || obj.format === "rsa-aes-v2")
    && obj.authMode === "credentials"
    && typeof obj.userHashSalt === "string"
    && typeof obj.credentialsByUserHash === "object"
    && obj.credentialsByUserHash !== null;
}

function isSessionPayload(value: unknown): value is { authMode: "session"; cookies: Record<string, string> } {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return obj.authMode === "session" && typeof obj.cookies === "object" && obj.cookies !== null;
}

export function detectStoredAuthMode(payload: string): AuthMode {
  try {
    const parsed = JSON.parse(payload);
    if (isCredentialEnvelope(parsed)) {
      return "credentials";
    }
  } catch {
    // not JSON envelope; try AES session payload below.
  }

  const parsed = decryptJson<unknown>(payload);
  if (isSessionPayload(parsed)) {
    return "session";
  }

  // Strict mode: old payloads without explicit authMode are considered invalid.
  throw new Error("Unsupported stored credential format. Reconfiguration required.");
}

export function encryptSessionPayload(value: unknown) {
  return encryptJson(value);
}

export function encryptCredentialsPayloadForUser(
  userId: string,
  fields: Fields,
  session?: StoredPlatformSession
) {
  const publicKey = getPublicKey();
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const storedValue: StoredCredentialsV2 = {
    credentials: fields,
    ...(session ? { session } : {}),
  };
  const plaintext = Buffer.from(JSON.stringify(storedValue), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const wrappedKey = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  const userHashSalt = randomBytes(16).toString("base64");
  const userHash = hashUserId(userId, userHashSalt);

  const envelope: CredentialEnvelopeV2 = {
    format: "rsa-aes-v2",
    authMode: "credentials",
    userHashSalt,
    credentialsByUserHash: {
      [userHash]: {
        wrappedKey: wrappedKey.toString("base64"),
        iv: iv.toString("base64"),
        tag: tag.toString("base64"),
        ciphertext: ciphertext.toString("base64"),
      },
    },
    createdAt: new Date().toISOString(),
  };

  return JSON.stringify(envelope);
}

function decryptCredentialEnvelopeValue(payload: string, userId: string) {
  const parsed = JSON.parse(payload) as unknown;
  if (!isCredentialEnvelope(parsed)) {
    throw new Error("Invalid credentials envelope");
  }

  const privateKey = getPrivateKey();
  const userHash = hashUserId(userId, parsed.userHashSalt);
  const entry = parsed.credentialsByUserHash[userHash];
  if (!entry) {
    throw new Error("Credentials entry not found for user");
  }

  const aesKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(entry.wrappedKey, "base64")
  );

  const decipher = createDecipheriv("aes-256-gcm", aesKey, Buffer.from(entry.iv, "base64"));
  decipher.setAuthTag(Buffer.from(entry.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(entry.ciphertext, "base64")),
    decipher.final(),
  ]);

  const value = JSON.parse(plaintext.toString("utf8")) as unknown;
  if (!value || typeof value !== "object") {
    throw new Error("Invalid decrypted credentials payload");
  }
  return { envelope: parsed, value: value as Record<string, unknown> };
}

export function decryptCredentialsPayloadForUser(payload: string, userId: string): Fields {
  const { envelope, value } = decryptCredentialEnvelopeValue(payload, userId);
  if (envelope.format === "rsa-aes-v1") {
    return value as Fields;
  }

  const credentials = value.credentials;
  if (!credentials || typeof credentials !== "object" || Array.isArray(credentials)) {
    throw new Error("Invalid credentials payload");
  }
  return credentials as Fields;
}

export function decryptStoredPlatformDataForUser(payload: string, userId: string): StoredPlatformData {
  const mode = detectStoredAuthMode(payload);
  if (mode === "credentials") {
    const { envelope, value } = decryptCredentialEnvelopeValue(payload, userId);
    if (envelope.format === "rsa-aes-v1") {
      return { authMode: "credentials", credentials: value as Fields };
    }

    const credentials = value.credentials;
    if (!credentials || typeof credentials !== "object" || Array.isArray(credentials)) {
      throw new Error("Invalid credentials payload");
    }
    const session = value.session;
    if (session && (typeof session !== "object" || Array.isArray(session))) {
      throw new Error("Invalid stored session payload");
    }
    const storedSession = session as StoredPlatformSession | undefined;
    return {
      authMode: "credentials",
      credentials: credentials as Fields,
      ...(storedSession?.cookies ? { cookies: storedSession.cookies } : {}),
      ...(storedSession?.url ? { url: storedSession.url } : {}),
    };
  }

  const parsed = decryptJson<unknown>(payload);
  if (!isSessionPayload(parsed)) {
    throw new Error("Invalid session payload format. Reconfiguration required.");
  }
  return parsed as StoredPlatformData;
}
