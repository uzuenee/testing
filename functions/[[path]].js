export async function onRequest(context) {
    const { request, env, next } = context;
    const url = new URL(request.url);
    const path = url.pathname;
  
    if (path === "/api/login" && request.method === "POST") return handleLogin(request, env);
    if (path === "/api/logout" && request.method === "POST") return handleLogout();
    if (path === "/api/session") return handleSession(request, env);
    if (path === "/api/models") return requireAuth(request, env, handleModels);
    if (path === "/api/chat" && request.method === "POST") return requireAuth(request, env, handleChat);
  
    return next();
  }
  
  /* --------------------------
  Utils
  ---------------------------*/
  
  function json(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json", ...headers }
    });
  }
  function text(body, status = 200, headers = {}) {
    return new Response(body, { status, headers });
  }
  
  function parseCookies(request) {
    const header = request.headers.get("Cookie") || "";
    const out = {};
    header.split(";").forEach(p => {
      const idx = p.indexOf("=");
      if (idx === -1) return;
      const k = p.slice(0, idx);
      const v = p.slice(idx + 1);
      if (!k) return;
      out[k.trim()] = decodeURIComponent((v || "").trim());
    });
    return out;
  }
  function setCookie(name, value, opts = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`];
    if (opts.Path) parts.push(`Path=${opts.Path}`);
    if (opts.HttpOnly) parts.push("HttpOnly");
    if (opts.Secure) parts.push("Secure");
    if (opts.SameSite) parts.push(`SameSite=${opts.SameSite}`);
    if (opts["Max-Age"]) parts.push(`Max-Age=${opts["Max-Age"]}`);
    if (opts.Expires) parts.push(`Expires=${opts.Expires.toUTCString()}`);
    return parts.join("; ");
  }
  
  // Base64URL helpers (safe for binary)
  function base64urlEncodeBytes(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function base64urlEncodeString(s) {
    const bytes = new TextEncoder().encode(s);
    return base64urlEncodeBytes(bytes);
  }
  function base64urlDecodeToBytes(b64url) {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (b64.length % 4)) % 4;
    const bin = atob(b64 + "=".repeat(padLen));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function utf8BytesToString(bytes) {
    return new TextDecoder().decode(bytes);
  }
  
  // Minimal JWT HS256
  async function signJWT(payload, secret) {
    const enc = new TextEncoder();
    const header = { alg: "HS256", typ: "JWT" };
    const headerB64 = base64urlEncodeString(JSON.stringify(header));
    const payloadB64 = base64urlEncodeString(JSON.stringify(payload));
    const data = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign({ name: "HMAC" }, key, enc.encode(data));
    const sigB64 = base64urlEncodeBytes(new Uint8Array(sig));
    return `${data}.${sigB64}`;
  }
  async function verifyJWT(token, secret) {
    try {
      const enc = new TextEncoder();
      const [h, p, s] = token.split(".");
      if (!h || !p || !s) return null;
      const data = `${h}.${p}`;
      const key = await crypto.subtle.importKey(
        "raw",
        enc.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
      );
      const sigBytes = base64urlDecodeToBytes(s);
      const ok = await crypto.subtle.verify({ name: "HMAC" }, key, sigBytes, enc.encode(data));
      if (!ok) return null;
      const payload = JSON.parse(utf8BytesToString(base64urlDecodeToBytes(p)));
      if (payload.exp && Date.now() >= payload.exp) return null;
      return payload;
    } catch {
      return null;
    }
  }
  
  async function getUserFromCookie(request, env) {
    const cookies = parseCookies(request);
    const token = cookies["session"] || "";
    if (!token) return null;
    const payload = await verifyJWT(token, env.SESSION_SECRET || "dev_session_secret_change_me");
    if (!payload) return null;
    return payload;
  }
  
  async function requireAuth(request, env, handler) {
    const user = await getUserFromCookie(request, env);
    if (!user) return json({ error: "Unauthorized" }, 401);
    return handler(request, env, user);
  }
  
  /* --------------------------
  Handlers
  ---------------------------*/
  async function handleLogin(request, env) {
    const { username, password } = await safeJson(request);
    const expectedUser = env.APP_USERNAME || "admin";
    const expectedPass = env.APP_PASSWORD || "admin123";
    if (!username || !password) return text("Missing username/password", 400);
    if (username !== expectedUser || password !== expectedPass) {
      await sleep(300);
      return text("Invalid credentials", 401);
    }
    const now = Date.now();
    const payload = { sub: username, iat: now, exp: now + 1000 * 60 * 60 * 24 * 30 }; // 30 days
    const token = await signJWT(payload, env.SESSION_SECRET || "dev_session_secret_change_me");
    const cookie = setCookie("session", token, {
      Path: "/",
      HttpOnly: true,
      Secure: true,
      SameSite: "Strict",
      "Max-Age": 60 * 60 * 24 * 30
    });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Set-Cookie": cookie }
    });
  }
  
  async function handleLogout() {
    const cookie = setCookie("session", "", {
      Path: "/",
      HttpOnly: true,
      Secure: true,
      SameSite: "Strict",
      "Max-Age": 0
    });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Set-Cookie": cookie }
    });
  }
  
  async function handleSession(request, env) {
    const user = await getUserFromCookie(request, env);
    return json({ authenticated: !!user });
  }
  
  async function handleModels() {
    return json({
      models: ["gpt-4o", "gpt-4o-mini", "o4-mini", "o3-mini"]
    });
  }
  
  async function handleChat(request, env /*, user */) {
    if (!env.OPENAI_API_KEY) {
      return text("Server missing OPENAI_API_KEY", 500);
    }
    const body = await safeJson(request);
    const model = body && body.model ? String(body.model) : "gpt-4o-mini";
    const clientMessages = Array.isArray(body.messages) ? body.messages : [];
    const settings = body.settings || {};
    const systemPrompt = (body.system || "You are a helpful assistant.").trim();
    const verbosity = normalizeVerbosity(body.verbosity);
  
    const verbGuide = verbosityToInstruction(verbosity);
    const finalSystem = [systemPrompt, verbGuide].filter(Boolean).join("\n\n");
  
    const sanitizedHistory = sanitizeMessages(clientMessages);
    const isReasoning = looksLikeReasoningModel(model);
  
    try {
      if (isReasoning) {
        // Responses API for o3/o4-style models
        const input = toResponsesInput([{ role: "system", content: finalSystem }, ...sanitizedHistory]);
        const payload = {
          model,
          input,
          reasoning: { effort: settings.reasoning_effort || "medium" } // only parameter we pass
        };
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            Authorization: "Bearer " + env.OPENAI_API_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        });
        if (!r.ok) {
          const err = await r.text();
          return text(err || "OpenAI error", r.status);
        }
        const data = await r.json();
        const reply = pickResponseText(data) || "(no reply)";
        return json({ reply });
      } else {
        // Chat Completions API for standard models (no temperature/top_p/max_tokens)
        const payload = {
          model,
          messages: [{ role: "system", content: finalSystem }, ...sanitizedHistory]
        };
        const r = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: "Bearer " + env.OPENAI_API_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        });
        if (!r.ok) {
          const err = await r.text();
          return text(err || "OpenAI error", r.status);
        }
        const data = await r.json();
        const reply =
          (data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) ||
          "(no reply)";
        return json({ reply });
      }
    } catch (err) {
      return text("Server error: " + (err && err.message ? err.message : String(err)), 500);
    }
  }
  
  /* --------------------------
  Helpers
  ---------------------------*/
  function sanitizeMessages(msgs) {
    const allowed = new Set(["user", "assistant"]);
    const out = [];
    for (const m of msgs) {
      if (!m || !m.role || !m.content) continue;
      const role = String(m.role);
      if (!allowed.has(role)) continue;
      const content = String(m.content);
      out.push({ role, content });
    }
    const MAX = 80;
    return out.slice(-MAX);
  }
  function looksLikeReasoningModel(model) {
    if (!model) return false;
    const x = model.toLowerCase();
    return x.startsWith("o3") || x.startsWith("o4") || x.includes("reasoning");
  }
  function toResponsesInput(messages) {
    return messages.map(m => {
      const role = m.role;
      const text = String(m.content || "");
      let type = "input_text";
      if (role === "system") type = "text";
      else if (role === "assistant") type = "output_text";
      else type = "input_text";
      return {
        role,
        content: [{ type, text }]
      };
    });
  }
  function pickResponseText(data) {
    if (!data) return "";
    if (typeof data.output_text === "string") return data.output_text;
    try {
      const out0 = data.output && data.output[0];
      if (out0 && out0.content && out0.content[0] && out0.content[0].text) {
        return out0.content[0].text;
      }
    } catch {}
    return "";
  }
  function normalizeVerbosity(v) {
    const s = String(v || "").toLowerCase();
    if (s === "low" || s === "medium" || s === "high") return s;
    return "medium";
  }
  function verbosityToInstruction(level) {
    const map = {
      low: "Be brief and to the point. Use minimal words.",
      medium: "Balance clarity and brevity. Provide enough detail to be helpful.",
      high: "Be thorough and explanatory. Include reasoning and examples where useful."
    };
    return "Verbosity guide: " + (map[level] || map.medium);
  }
  
  async function safeJson(request) {
    try {
      return await request.json();
    } catch {
      return {};
    }
  }
  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
  
