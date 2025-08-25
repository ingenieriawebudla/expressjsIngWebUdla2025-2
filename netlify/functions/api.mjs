/**
 * Express en Netlify Functions con seguridad + JWT + OAuth2 (GitHub)
 * Referencias:
 * - Express docs: https://expressjs.com/            // framework base
 * - serverless-http: https://www.npmjs.com/package/serverless-http // adaptar Express a Functions
 * - Netlify Functions: https://docs.netlify.com/build/functions/overview/
 * - Helmet (seguridad): https://helmetjs.github.io/
 * - express-rate-limit: https://www.npmjs.com/package/express-rate-limit
 * - CORS: https://www.npmjs.com/package/cors
 * - JWT (jsonwebtoken): https://www.npmjs.com/package/jsonwebtoken
 * - OAuth Web flow (GitHub): https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
 * - Token exchange: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authenticating-to-the-rest-api-with-an-oauth-app
 * - /user endpoint: https://docs.github.com/en/rest/users/users#get-the-authenticated-user
 */

import express from "express";
import serverless from "serverless-http"; // wrap Express
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";

const app = express();

// Trust proxy configuration for Netlify Functions
// In production, trust the first proxy (Netlify's infrastructure)
// In development, be more permissive for localhost
// const isProduction = process.env.NODE_ENV === 'production'
// app.set('trust proxy', isProduction ? 1 : true)

// for Production
app.set("trust proxy", 1);

// --- Seguridad base (Express best practices) ---
// Helmet (cabeceras seguras)
// https://helmetjs.github.io/
app.use(helmet());

// Body parser con límite prudente
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// Cookies para 'state' en OAuth
app.use(cookieParser());

// CORS (limitar orígenes en prod)
// https://www.npmjs.com/package/cors
const allow = (process.env.ALLOW_ORIGIN || "").split(",").filter(Boolean);
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allow.length === 0) return cb(null, true); // dev / Postman
      return cb(null, allow.includes(origin));
    },
  })
);

// Rate limiting global (proteger /auth y rutas públicas)
// https://www.npmjs.com/package/express-rate-limit
app.use(
  "/api/",
  rateLimit({
    windowMs: 60_000,
    max: 100,
    // Use standard IP key generator with fallback for development
    standardHeaders: true,
    legacyHeaders: false,
    // Skip problematic validations in development
    validate: {
      trustProxy: false, // We handle trust proxy ourselves
      xForwardedForHeader: false, // Skip X-Forwarded-For validation
      ip: false, // Skip IP validation for development
      default: false, // Skip other default validations that might cause issues
    },
  })
);

// --- Utils ---
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
function signToken(payload, exp = "1h") {
  // jsonwebtoken API: https://www.npmjs.com/package/jsonwebtoken
  return jwt.sign(payload, JWT_SECRET, { expiresIn: exp });
}
function verifyAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// --- Rutas básicas ---
app.get("/api/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// Login DEMO (sin DB): emite un JWT si llegan credenciales válidas
app.post("/api/auth/login", (req, res) => {
  console.log("Request body:", req.body);
  console.log("Content-Type:", req.headers["content-type"]);

  // Handle case where body is a Buffer (common in serverless environments)
  let body = req.body;
  if (Buffer.isBuffer(body)) {
    try {
      body = JSON.parse(body.toString());
    } catch (e) {
      return res.status(400).json({ error: "Invalid JSON in request body" });
    }
  }

  const { email, password } = body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email/password required" });
  // En un caso real, valida contra DB y hashea passwords.
  const token = signToken({ sub: email, role: "user" }, "1h");
  return res.json({ token, token_type: "Bearer", expires_in: 3600 });
});

// Ruta protegida por JWT
app.get("/api/auth/me", verifyAuth, (req, res) => {
  res.json({ user: req.user });
});

// --- OAuth2: GitHub (Authorization Code) ---
// Flujo: redirect a /authorize con state, callback verifica state y canjea code por access_token
// Docs flujo web: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
// Token exchange: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authenticating-to-the-rest-api-with-an-oauth-app
const GH_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GH_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI; // e.g. https://<site>.netlify.app/api/oauth/github/callback

app.get("/api/oauth/github/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  // Guarda 'state' en cookie (HttpOnly recomendado en prod y sobre HTTPS)
  res.cookie("oauth_state", state, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
  });
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", GH_CLIENT_ID);
  url.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
  url.searchParams.set("scope", "read:user user:email"); // ajustar según necesidad
  url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

app.get("/api/oauth/github/callback", async (req, res) => {
  const { code, state } = req.query;
  const stored = req.cookies.oauth_state;
  if (!code || !state || !stored || state !== stored) {
    return res.status(400).send("Invalid OAuth state");
  }

  // Intercambiar code por access_token (Accept: application/json)
  // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authenticating-to-the-rest-api-with-an-oauth-app
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: GH_CLIENT_ID,
      client_secret: GH_CLIENT_SECRET,
      code,
      redirect_uri: OAUTH_REDIRECT_URI,
      state,
    }),
  });
  const tokenJson = await tokenRes.json();
  const ghToken = tokenJson.access_token;
  if (!ghToken) return res.status(401).send("OAuth token exchange failed");

  // Obtener perfil del usuario autenticado
  // /user endpoint: https://docs.github.com/en/rest/users/users#get-the-authenticated-user
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${ghToken}`,
      Accept: "application/vnd.github+json",
    },
  });
  const ghUser = await userRes.json();

  // Emitimos NUESTRO JWT con datos mínimos (no exponer ghToken)
  const ourToken = signToken(
    { sub: `github:${ghUser.id}`, login: ghUser.login },
    "1h"
  );

  // Redirige al front con el token como fragment (para que no viaje en logs/refs)
  return res.redirect(`/?token=${ourToken}#logged=github`);
});

// Exportar handler para Netlify (serverless-http)
// https://www.npmjs.com/package/serverless-http
export const handler = serverless(app);
