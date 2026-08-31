/**
 * PHANTOM HUB — account backend (Cloudflare Worker + KV)
 *
 * Flow:
 *   1. POST /api/verify-start   { robloxUsername } -> generates a PHANTOM-xxxx code,
 *      stores it in KV under pending:<robloxId> for 30 minutes.
 *   2. User pastes the code into their Roblox profile "About" bio.
 *   3. POST /api/verify-complete { robloxUsername } -> re-checks the bio. If the code
 *      is present and not expired, creates (or confirms) the account and returns a
 *      signed session token. This same endpoint is used for BOTH first-time signup
 *      and every future login — logging in again just means proving you still own
 *      the Roblox account.
 *   4. GET  /api/me  (Authorization: Bearer <token>) -> validates the token and
 *      returns account info. No KV write happens here.
 *
 * KV writes only happen: once per new account (step 3, first time), and on admin
 * ban/unban. Everything else is a KV read or pure signature math, to stay well
 * inside the free tier's 1,000-writes/day KV limit.
 *
 * Required setup (wrangler.toml):
 *   - KV namespace binding: PHANTOM_KV
 *   - Secrets: TOKEN_SECRET (random long string), ADMIN_KEY (your admin password)
 */

const CODE_TTL_SECONDS = 30 * 60; // 30 minutes
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
const ADMIN_TTL_SECONDS = 12 * 60 * 60; // 12 hours

// ---------- small helpers ----------

function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "Content-Type,Authorization");
  return resp;
}

function json(data, status = 200) {
  return cors(
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  );
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

function randomCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  for (let i = 0; i < bytes.length; i++) out += chars[bytes[i] % chars.length];
  return "PHANTOM-" + out;
}

function b64url(bytes) {
  let str = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signToken(payload, secret) {
  const key = await hmacKey(secret);
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const payloadB64 = b64url(payloadBytes.buffer);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return payloadB64 + "." + b64url(sig);
}

async function verifyToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [payloadB64, sigB64] = token.split(".");
  const key = await hmacKey(secret);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    b64urlToBytes(sigB64),
    new TextEncoder().encode(payloadB64)
  );
  if (!valid) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getBearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

// ---------- Roblox lookups (server-side, no CORS issue here) ----------

async function resolveRobloxUser(username) {
  const res = await fetch("https://users.roblox.com/v1/usernames/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: false }),
  });
  if (!res.ok) return null;
  const data = await res.json();
  if (!data.data || !data.data[0]) return null;
  return { id: data.data[0].id, name: data.data[0].name };
}

async function getRobloxBio(userId) {
  const res = await fetch(`https://users.roblox.com/v1/users/${userId}`);
  if (!res.ok) return "";
  const data = await res.json();
  return data.description || "";
}

// ---------- route handlers ----------

async function handleVerifyStart(request, env) {
  const body = await request.json().catch(() => ({}));
  const robloxUsername = (body.robloxUsername || "").trim();
  if (!robloxUsername) return err("robloxUsername is required.");

  const user = await resolveRobloxUser(robloxUsername);
  if (!user) return err("That Roblox username doesn't exist.", 404);

  const code = randomCode();
  await env.PHANTOM_KV.put(
    `pending:${user.id}`,
    JSON.stringify({ code, robloxUsername: user.name, createdAt: Date.now() }),
    { expirationTtl: CODE_TTL_SECONDS }
  );

  return json({
    code,
    robloxUsername: user.name,
    expiresInSeconds: CODE_TTL_SECONDS,
    instructions:
      "Paste this code anywhere in your Roblox profile bio (About section), save it, then press Verify within 30 minutes.",
  });
}

async function handleVerifyComplete(request, env) {
  const body = await request.json().catch(() => ({}));
  const robloxUsername = (body.robloxUsername || "").trim();
  if (!robloxUsername) return err("robloxUsername is required.");

  const user = await resolveRobloxUser(robloxUsername);
  if (!user) return err("That Roblox username doesn't exist.", 404);

  const pendingRaw = await env.PHANTOM_KV.get(`pending:${user.id}`);
  if (!pendingRaw) {
    return err("No pending code found (or it expired). Generate a new one.", 410);
  }
  const pending = JSON.parse(pendingRaw);

  const bio = await getRobloxBio(user.id);
  if (!bio.includes(pending.code)) {
    return err("Code not found in your bio yet. Make sure you saved your profile.", 409);
  }

  const existingRaw = await env.PHANTOM_KV.get(`account:${user.id}`);
  let account;
  if (existingRaw) {
    account = JSON.parse(existingRaw);
    if (account.banned) return err("This account is banned.", 403);
  } else {
    account = {
      robloxId: user.id,
      robloxUsername: user.name,
      createdAt: Date.now(),
      banned: false,
    };
    await env.PHANTOM_KV.put(`account:${user.id}`, JSON.stringify(account));
  }

  await env.PHANTOM_KV.delete(`pending:${user.id}`);

  const token = await signToken(
    { robloxId: user.id, robloxUsername: user.name, exp: Date.now() + SESSION_TTL_SECONDS * 1000 },
    env.TOKEN_SECRET
  );

  return json({ token, robloxUsername: user.name, robloxId: user.id });
}

async function handleMe(request, env) {
  const token = getBearer(request);
  const payload = await verifyToken(token, env.TOKEN_SECRET);
  if (!payload) return err("Invalid or expired session.", 401);

  const raw = await env.PHANTOM_KV.get(`account:${payload.robloxId}`);
  if (!raw) return err("Account not found.", 404);
  const account = JSON.parse(raw);
  if (account.banned) return err("This account is banned.", 403);

  return json({ robloxUsername: account.robloxUsername, robloxId: account.robloxId, createdAt: account.createdAt });
}

async function handleAdminLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!body.adminKey || body.adminKey !== env.ADMIN_KEY) {
    return err("Invalid admin key.", 401);
  }
  const token = await signToken({ admin: true, exp: Date.now() + ADMIN_TTL_SECONDS * 1000 }, env.TOKEN_SECRET);
  return json({ token });
}

async function requireAdmin(request, env) {
  const token = getBearer(request);
  const payload = await verifyToken(token, env.TOKEN_SECRET);
  if (!payload || !payload.admin) return null;
  return payload;
}

async function handleAdminAccounts(request, env) {
  if (!(await requireAdmin(request, env))) return err("Unauthorized.", 401);

  const list = await env.PHANTOM_KV.list({ prefix: "account:" });
  const accounts = await Promise.all(
    list.keys.map(async (k) => {
      const raw = await env.PHANTOM_KV.get(k.name);
      return raw ? JSON.parse(raw) : null;
    })
  );
  return json({ accounts: accounts.filter(Boolean) });
}

async function handleAdminBan(request, env) {
  if (!(await requireAdmin(request, env))) return err("Unauthorized.", 401);

  const body = await request.json().catch(() => ({}));
  if (!body.robloxId) return err("robloxId is required.");

  const raw = await env.PHANTOM_KV.get(`account:${body.robloxId}`);
  if (!raw) return err("Account not found.", 404);
  const account = JSON.parse(raw);
  account.banned = !!body.banned;
  await env.PHANTOM_KV.put(`account:${body.robloxId}`, JSON.stringify(account));

  return json({ ok: true, account });
}

// ---------- router ----------

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    const url = new URL(request.url);
    const { pathname } = url;

    try {
      if (pathname === "/api/verify-start" && request.method === "POST") return handleVerifyStart(request, env);
      if (pathname === "/api/verify-complete" && request.method === "POST") return handleVerifyComplete(request, env);
      if (pathname === "/api/me" && request.method === "GET") return handleMe(request, env);
      if (pathname === "/api/admin/login" && request.method === "POST") return handleAdminLogin(request, env);
      if (pathname === "/api/admin/accounts" && request.method === "GET") return handleAdminAccounts(request, env);
      if (pathname === "/api/admin/ban" && request.method === "POST") return handleAdminBan(request, env);
      return err("Not found.", 404);
    } catch (e) {
      return err("Server error: " + e.message, 500);
    }
  },
};
