/**
 * MNnote+ — خادم المعلم الذكي (Cloudflare Worker)
 *
 * ما يفعله: يستقبل الطلب من التطبيق مع رمز تسجيل الدخول (Firebase ID token)،
 * يتحقق من صحة الرمز (توقيع Google + معرّف مشروع Firebase + الصلاحية)،
 * يطبّق حدّاً يومياً لكل حساب، ثم يستدعي Gemini بمفتاحك السري المحفوظ هنا فقط.
 *
 * المتغيرات (Settings → Variables and Secrets في Cloudflare):
 *   GEMINI_API_KEY   (Secret)  مفتاح Gemini الخاص بك                      [مطلوب]
 *   FIREBASE_PROJECT_ID (Text) معرّف مشروع Firebase، مثل: mnnote-6be08  [مطلوب]
 *   ALLOWED_ORIGINS  (Text)    رابط موقعك فقط، مثل: https://name.github.io [مطلوب]
 *   DAILY_LIMIT      (Text)    عدد الطلبات اليومية لكل حساب (الافتراضي 40)
 *   ALLOWED_EMAILS   (Text)    إيميلات مسموحة مفصولة بفواصل (اختياري)
 *   ALLOWED_DOMAINS  (Text)    نطاقات مسموحة مثل: univ.edu,gmail.com (اختياري)
 *   GEMINI_MODEL     (Text)    اسم النموذج (الافتراضي gemini-2.5-flash)
 *   LIMITS           (KV)      ربط مساحة KV لحفظ العدّاد اليومي بدقة (اختياري لكن موصى به)
 */
const CERTS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
let certCache = { keys: null, exp: 0 };
const mem = new Map();
const td = new TextDecoder();

const b64u = s => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
};

async function getKeys() {
  if (certCache.keys && Date.now() < certCache.exp) return certCache.keys;
  const r = await fetch(CERTS_URL);
  if (!r.ok) throw new Error("certs");
  const j = await r.json();
  const m = (r.headers.get("cache-control") || "").match(/max-age=(\d+)/);
  certCache = { keys: j.keys, exp: Date.now() + (m ? +m[1] : 3600) * 1000 };
  return j.keys;
}

/** يتحقق من رمز هوية Google ويعيد بياناته أو null */
export async function verifyIdToken(token, projectId) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(td.decode(b64u(parts[0])));
    payload = JSON.parse(td.decode(b64u(parts[1])));
  } catch (e) { return null; }
  if (header.alg !== "RS256") return null;
  let keys;
  try { keys = await getKeys(); } catch (e) { return null; }
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  if (!ok) return null;
  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== "https://securetoken.google.com/" + projectId) return null;
  if (payload.aud !== projectId) return null;
  if (!(payload.exp > now)) return null;
  if (!payload.sub) return null;
  return payload;
}

const day = () => new Date().toISOString().slice(0, 10);
async function underLimit(env, sub) {
  const limit = parseInt(env.DAILY_LIMIT || "40", 10);
  if (!env.LIMITS) {
    const k = sub + ":" + day();
    const n = (mem.get(k) || 0) + 1;
    mem.set(k, n);
    if (mem.size > 5000) mem.clear();
    return n <= limit;
  }
  const k = "u:" + sub + ":" + day();
  const cur = parseInt((await env.LIMITS.get(k)) || "0", 10);
  if (cur >= limit) return false;
  await env.LIMITS.put(k, String(cur + 1), { expirationTtl: 172800 });
  return true;
}

function allowedUser(env, p) {
  const email = String(p.email || "").toLowerCase();
  const emails = (env.ALLOWED_EMAILS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean);
  const domains = (env.ALLOWED_DOMAINS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean);
  if (!emails.length && !domains.length) return true;
  return emails.includes(email) || domains.includes(email.split("@")[1] || "");
}

async function callGemini(env, prompt, wantJson) {
  const models = [env.GEMINI_MODEL || "gemini-2.5-flash", "gemini-2.5-flash", "gemini-flash-latest"].filter((m, i, a) => m && a.indexOf(m) === i);
  const body = JSON.stringify({
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: Object.assign({ temperature: 0.4 }, wantJson ? { responseMimeType: "application/json" } : {})
  });
  for (const m of models) {
    const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(m) + ":generateContent", {
      method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY }, body
    });
    if (r.status === 404) continue;
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return { status: r.status === 429 ? 429 : 502, error: (j.error && j.error.message) || "gemini" };
    const parts = (j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || [];
    const text = parts.map(x => x.text || "").join("");
    if (!text) return { status: 502, error: "empty" };
    return { status: 200, text };
  }
  return { status: 502, error: "model" };
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim().replace(/\/$/, "")).filter(Boolean);
    const cors = {
      "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : (allowed[0] || "null"),
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin"
    };
    const out = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST") return out({ error: "method" }, 405);
    if (!env.GEMINI_API_KEY || !env.FIREBASE_PROJECT_ID) return out({ error: "server_not_configured" }, 500);
    if (allowed.length && !allowed.includes(origin)) return out({ error: "origin" }, 403);

    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const user = await verifyIdToken(token, env.FIREBASE_PROJECT_ID);
    if (!user) return out({ error: "unauthorized" }, 401);
    if (!allowedUser(env, user)) return out({ error: "forbidden" }, 403);

    let body;
    try { body = await req.json(); } catch (e) { return out({ error: "bad_json" }, 400); }
    const prompt = typeof body.prompt === "string" ? body.prompt : "";
    if (!prompt.trim()) return out({ error: "empty_prompt" }, 400);
    if (prompt.length > 24000) return out({ error: "prompt_too_long" }, 413);

    if (!(await underLimit(env, user.sub))) return out({ error: "daily_limit" }, 429);

    const r = await callGemini(env, prompt, !!body.json);
    if (r.status !== 200) return out({ error: r.error }, r.status);
    return out({ text: r.text });
  }
};
