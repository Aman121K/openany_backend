import express from "express";
import cors from "cors";
import { spawn, execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5050;

// In production, set JWT_SECRET as a real environment variable.
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-insecure-secret-change-me";
const USERS_FILE = path.join(process.cwd(), "users.json");
const HISTORY_FILE = path.join(process.cwd(), "history.json");

// Optional: path to a Netscape-format cookies.txt file (exported from a
// logged-in browser session) for sites like Instagram/Facebook that block
// or rate-limit anonymous requests from datacenter IPs more aggressively
// than from a real logged-in session. Set YTDLP_COOKIES_FILE to enable.
const COOKIES_FILE = process.env.YTDLP_COOKIES_FILE || path.join(process.cwd(), "cookies.txt");
const cookiesArgs = () => (fs.existsSync(COOKIES_FILE) ? ["--cookies", COOKIES_FILE] : []);

function readJsonFile(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return fallback;
  }
}

function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function readUsers() {
  return readJsonFile(USERS_FILE, []);
}

function readHistory() {
  return readJsonFile(HISTORY_FILE, {});
}

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.name }, JWT_SECRET, {
    expiresIn: "30d",
  });
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email };
}

// Verifies the Bearer token if present; attaches req.user. Does not
// reject unauthenticated requests — auth is optional across the app.
function optionalAuth(req, _res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = { id: payload.sub, email: payload.email, name: payload.name };
    } catch {
      req.user = null;
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Please log in to continue." });
  }
  next();
}

app.use(optionalAuth);

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTACT_FILE = path.join(process.cwd(), "contact-submissions.json");

function readSubmissions() {
  try {
    return JSON.parse(fs.readFileSync(CONTACT_FILE, "utf-8"));
  } catch {
    return [];
  }
}

// ---------- Auth (optional — used only for saving history to an account) ----------

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: "Please enter your name." });
  }
  if (!email || !EMAIL_RE.test(String(email).trim())) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  const users = readUsers();
  const normalizedEmail = String(email).trim().toLowerCase();
  if (users.some((u) => u.email === normalizedEmail)) {
    return res.status(409).json({ error: "An account with this email already exists." });
  }

  const user = {
    id: crypto.randomUUID(),
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash: await bcrypt.hash(String(password), 10),
    createdAt: new Date().toISOString(),
  };

  users.push(user);
  writeJsonFile(USERS_FILE, users);

  res.json({ token: signToken(user), user: publicUser(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Please enter your email and password." });
  }

  const users = readUsers();
  const normalizedEmail = String(email).trim().toLowerCase();
  const user = users.find((u) => u.email === normalizedEmail);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const ok = await bcrypt.compare(String(password), user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  res.json({ token: signToken(user), user: publicUser(user) });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const users = readUsers();
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found." });
  res.json({ user: publicUser(user) });
});

// ---------- History (optional cloud sync for logged-in users) ----------

app.get("/api/history", requireAuth, (req, res) => {
  const history = readHistory();
  res.json({ history: history[req.user.id] || [] });
});

app.post("/api/history", requireAuth, (req, res) => {
  const { entry } = req.body || {};
  if (!entry || !entry.sourceUrl) {
    return res.status(400).json({ error: "Invalid history entry." });
  }

  const history = readHistory();
  const current = (history[req.user.id] || []).filter(
    (h) => h.sourceUrl !== entry.sourceUrl
  );
  current.unshift({ ...entry, savedAt: new Date().toISOString() });
  history[req.user.id] = current.slice(0, 20);
  writeJsonFile(HISTORY_FILE, history);

  res.json({ history: history[req.user.id] });
});

app.delete("/api/history", requireAuth, (req, res) => {
  const history = readHistory();
  history[req.user.id] = [];
  writeJsonFile(HISTORY_FILE, history);
  res.json({ history: [] });
});

// Receive a contact form submission and store it locally.
app.post("/api/contact", (req, res) => {
  const { name, email, message } = req.body || {};

  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: "Please enter your name." });
  }
  if (!email || !EMAIL_RE.test(String(email).trim())) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (!message || String(message).trim().length < 10) {
    return res.status(400).json({ error: "Message should be at least 10 characters." });
  }
  if (String(name).length > 200 || String(email).length > 200 || String(message).length > 5000) {
    return res.status(400).json({ error: "Input is too long." });
  }

  const entry = {
    id: crypto.randomUUID(),
    name: String(name).trim(),
    email: String(email).trim(),
    message: String(message).trim(),
    receivedAt: new Date().toISOString(),
  };

  try {
    const submissions = readSubmissions();
    submissions.push(entry);
    fs.writeFileSync(CONTACT_FILE, JSON.stringify(submissions, null, 2));
  } catch {
    return res.status(500).json({ error: "Could not save your message. Please try again." });
  }

  res.json({ success: true });
});

const BROWSER_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
};

function metaContent(html, ...properties) {
  for (const prop of properties) {
    const re = new RegExp(
      `<meta[^>]+(?:property|name)=["']${prop}["'][^>]+content=["']([^"']+)["']`,
      "i"
    );
    const match = html.match(re);
    if (match) return decodeHtmlEntities(match[1]);
  }
  return null;
}

function decodeHtmlEntities(str) {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}

// Best-effort fallback for sites yt-dlp doesn't have a dedicated extractor
// for: fetch the page HTML and look for a video URL exposed via Open Graph
// tags, a <video>/<source> element, or a raw .mp4/.m3u8 link in the markup.
// Works only when the media URL is present in the initial server-rendered
// HTML — sites that load video via JS after the page loads (many modern
// apps) won't be found this way.
async function tryGenericExtract(url) {
  const res = await fetch(url, { headers: BROWSER_HEADERS, redirect: "follow" });
  if (!res.ok) return null;
  const html = await res.text();

  const videoUrl =
    metaContent(html, "og:video:secure_url", "og:video:url", "og:video", "twitter:player:stream") ||
    html.match(/<video[^>]+src=["']([^"']+)["']/i)?.[1] ||
    html.match(/<source[^>]+src=["']([^"']+\.(?:mp4|m3u8)[^"']*)["']/i)?.[1] ||
    html.match(/https?:\/\/[^"'\s\\]+\.mp4[^"'\s\\]*/i)?.[0];

  if (!videoUrl) return null;

  const title = metaContent(html, "og:title", "twitter:title") || "Downloaded video";
  const thumbnail = metaContent(html, "og:image", "twitter:image");
  const resolvedVideoUrl = new URL(decodeHtmlEntities(videoUrl), url).toString();

  return {
    title,
    thumbnail,
    duration: null,
    uploader: null,
    extractor: "generic (best-effort)",
    formats: [
      {
        format_id: "generic",
        ext: resolvedVideoUrl.includes(".m3u8") ? "m3u8" : "mp4",
        resolution: "original",
        filesize: null,
        hasVideo: true,
        hasAudio: true,
        directUrl: resolvedVideoUrl,
      },
    ],
  };
}

// Fetch video metadata + available formats using yt-dlp, with a generic
// HTML-scraping fallback for platforms yt-dlp doesn't support.
app.post("/api/info", async (req, res) => {
  const { url } = req.body || {};
  if (!url || !isValidUrl(url)) {
    return res.status(400).json({ error: "Please provide a valid video URL." });
  }

  execFile(
    "yt-dlp",
    ["-j", "--no-playlist", ...cookiesArgs(), url],
    { maxBuffer: 1024 * 1024 * 20, timeout: 90000 },
    async (err, stdout) => {
      if (err) {
        try {
          const fallback = await tryGenericExtract(url);
          if (fallback) return res.json(fallback);
        } catch {
          // fall through to the error response below
        }
        return res.status(422).json({
          error: "Could not fetch video info. The link may be private, unsupported, or invalid.",
        });
      }
      try {
        const data = JSON.parse(stdout);
        const formats = (data.formats || [])
          .filter((f) => f.url && (f.vcodec !== "none" || f.acodec !== "none"))
          .map((f) => ({
            format_id: f.format_id,
            ext: f.ext,
            resolution: f.resolution || (f.height ? `${f.height}p` : "audio"),
            filesize: f.filesize || f.filesize_approx || null,
            hasVideo: f.vcodec && f.vcodec !== "none",
            hasAudio: f.acodec && f.acodec !== "none",
          }))
          .reverse();

        res.json({
          title: data.title,
          thumbnail: data.thumbnail,
          duration: data.duration,
          uploader: data.uploader,
          extractor: data.extractor,
          formats,
        });
      } catch {
        res.status(500).json({ error: "Failed to parse video info." });
      }
    }
  );
});

// Download the video to a temp file, stream it to the browser, then clean up
app.get("/api/download", async (req, res) => {
  const { url, format_id, media_url } = req.query;
  if (!url || !isValidUrl(url)) {
    return res.status(400).json({ error: "Invalid URL." });
  }

  // Generic fallback: stream the direct media URL we scraped from the page,
  // rather than invoking yt-dlp (which has no extractor for this site).
  if (format_id === "generic") {
    if (!media_url || !isValidUrl(media_url)) {
      return res.status(400).json({ error: "Missing media URL." });
    }
    try {
      const upstream = await fetch(media_url, { headers: BROWSER_HEADERS });
      if (!upstream.ok || !upstream.body) {
        return res.status(422).json({ error: "Could not download this video." });
      }
      const ext = String(media_url).includes(".m3u8") ? "m3u8" : "mp4";
      res.setHeader("Content-Disposition", `attachment; filename="video.${ext}"`);
      res.setHeader("Content-Type", upstream.headers.get("content-type") || "video/mp4");
      const contentLength = upstream.headers.get("content-length");
      if (contentLength) res.setHeader("Content-Length", contentLength);

      const reader = upstream.body;
      for await (const chunk of reader) {
        if (!res.write(chunk)) {
          await new Promise((resolve) => res.once("drain", resolve));
        }
      }
      return res.end();
    } catch {
      if (!res.headersSent) return res.status(500).json({ error: "Download failed." });
      return res.end();
    }
  }

  const jobId = crypto.randomUUID();
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), `vdl-${jobId}-`));
  const outTemplate = path.join(outDir, "output.%(ext)s");

  const args = [
    "-o", outTemplate,
    "--no-playlist",
    "--no-part",
    "--merge-output-format", "mp4",
    ...cookiesArgs(),
  ];
  if (format_id) {
    args.push("-f", `${format_id}+bestaudio/${format_id}/best`);
  } else {
    args.push("-f", "bestvideo+bestaudio/best");
  }
  args.push(String(url));

  const cleanup = () => fs.rm(outDir, { recursive: true, force: true }, () => {});

  const proc = spawn("yt-dlp", args);
  let stderr = "";
  proc.stderr.on("data", (d) => (stderr += d.toString()));

  proc.on("close", (code) => {
    if (code !== 0) {
      cleanup();
      if (!res.headersSent) {
        return res.status(422).json({ error: "Failed to download this video." });
      }
      return;
    }

    const files = fs.readdirSync(outDir);
    if (files.length === 0) {
      cleanup();
      return res.status(500).json({ error: "No output file produced." });
    }

    const filePath = path.join(outDir, files[0]);
    const ext = path.extname(files[0]) || ".mp4";

    res.setHeader("Content-Disposition", `attachment; filename="video${ext}"`);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", fs.statSync(filePath).size);

    const readStream = fs.createReadStream(filePath);
    readStream.pipe(res);
    readStream.on("close", cleanup);
    readStream.on("error", cleanup);
  });

  proc.on("error", () => {
    cleanup();
    if (!res.headersSent) res.status(500).end();
  });

  req.on("close", () => {
    if (!res.writableEnded) {
      proc.kill("SIGKILL");
      cleanup();
    }
  });
});

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
