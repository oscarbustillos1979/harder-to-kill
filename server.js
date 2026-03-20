const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Config ---
const WHOOP_CLIENT_ID = process.env.WHOOP_CLIENT_ID;
const WHOOP_CLIENT_SECRET = process.env.WHOOP_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const WHOOP_AUTH_URL = "https://api.prod.whoop.com/oauth/oauth2/auth";
const WHOOP_TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token";
const WHOOP_API_BASE = "https://api.prod.whoop.com/developer";
const SCOPES = "read:recovery read:sleep read:cycles read:workout read:profile offline";

// --- Middleware ---
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    },
    ...(process.env.NODE_ENV === "production" && { proxy: true }),
  })
);

if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// --- Token helpers ---

async function exchangeCodeForTokens(code) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: WHOOP_CLIENT_ID,
    client_secret: WHOOP_CLIENT_SECRET,
    redirect_uri: `${BASE_URL}/auth/callback`,
  });

  const res = await fetch(WHOOP_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }
  return res.json();
}

async function refreshAccessToken(refreshToken) {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: WHOOP_CLIENT_ID,
    client_secret: WHOOP_CLIENT_SECRET,
  });

  const res = await fetch(WHOOP_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token refresh failed (${res.status}): ${text}`);
  }
  return res.json();
}

async function getValidToken(session) {
  if (!session.tokens) return null;

  const now = Date.now();
  // Refresh if token expires within 5 minutes
  if (session.tokens.expires_at && now > session.tokens.expires_at - 5 * 60 * 1000) {
    if (!session.tokens.refresh_token) return null;
    try {
      const data = await refreshAccessToken(session.tokens.refresh_token);
      session.tokens = {
        access_token: data.access_token,
        refresh_token: data.refresh_token || session.tokens.refresh_token,
        expires_at: Date.now() + data.expires_in * 1000,
      };
    } catch (err) {
      console.error("Token refresh error:", err.message);
      session.tokens = null;
      return null;
    }
  }

  return session.tokens.access_token;
}

async function whoopGet(endpoint, accessToken) {
  const res = await fetch(`${WHOOP_API_BASE}${endpoint}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Whoop API ${endpoint} failed (${res.status}): ${text}`);
  }
  return res.json();
}

// --- Auth routes ---

app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: WHOOP_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/callback`,
    scope: SCOPES,
    state,
  });

  res.redirect(`${WHOOP_AUTH_URL}?${params.toString()}`);
});

app.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error("OAuth error:", error);
    return res.redirect("/?error=oauth_denied");
  }

  if (!code || state !== req.session.oauthState) {
    return res.redirect("/?error=invalid_state");
  }

  delete req.session.oauthState;

  try {
    const data = await exchangeCodeForTokens(code);
    req.session.tokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + data.expires_in * 1000,
    };
    res.redirect("/");
  } catch (err) {
    console.error("Token exchange error:", err.message);
    res.redirect("/?error=token_exchange");
  }
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/auth/status", (req, res) => {
  res.json({ authenticated: !!req.session.tokens });
});

// --- API routes ---

app.get("/api/today", async (req, res) => {
  const accessToken = await getValidToken(req.session);
  if (!accessToken) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    // Fetch recovery, sleep, and cycle data in parallel
    const [recoveryData, sleepData, cycleData] = await Promise.allSettled([
      whoopGet("/v1/recovery?limit=1&order=desc", accessToken),
      whoopGet("/v1/activity/sleep?limit=1&order=desc", accessToken),
      whoopGet("/v1/cycle?limit=1&order=desc", accessToken),
    ]);

    const recovery = recoveryData.status === "fulfilled" ? recoveryData.value : null;
    const sleep = sleepData.status === "fulfilled" ? sleepData.value : null;
    const cycle = cycleData.status === "fulfilled" ? cycleData.value : null;

    // Extract latest records
    const latestRecovery = recovery?.records?.[0]?.score || null;
    const latestSleep = sleep?.records?.[0]?.score || null;
    const latestCycle = cycle?.records?.[0]?.score || null;

    res.json({
      timestamp: new Date().toISOString(),
      recovery: latestRecovery
        ? {
            score: latestRecovery.recovery_score,
            hrv: latestRecovery.hrv_rmssd_milli,
            resting_hr: latestRecovery.resting_heart_rate,
          }
        : null,
      sleep: latestSleep
        ? {
            performance: latestSleep.sleep_performance_percentage,
            duration_hours: latestSleep.stage_summary
              ? +(
                  (latestSleep.stage_summary.total_in_bed_time_milli || 0) /
                  3600000
                ).toFixed(1)
              : null,
          }
        : null,
      strain: latestCycle
        ? {
            day_strain: latestCycle.strain,
            avg_hr: latestCycle.average_heart_rate,
            max_hr: latestCycle.max_heart_rate,
            calories: latestCycle.kilojoule
              ? +(latestCycle.kilojoule * 0.239006).toFixed(0)
              : null,
          }
        : null,
    });
  } catch (err) {
    console.error("API fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch Whoop data" });
  }
});

// --- Serve dashboard ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`Harder to Kill running on port ${PORT}`);
  if (!WHOOP_CLIENT_ID || !WHOOP_CLIENT_SECRET) {
    console.warn("WARNING: WHOOP_CLIENT_ID and/or WHOOP_CLIENT_SECRET not set");
  }
});
