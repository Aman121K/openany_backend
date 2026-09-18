import express from "express";
import cors from "cors";
import { spawn, execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5050;

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// Fetch video metadata + available formats using yt-dlp
app.post("/api/info", (req, res) => {
  const { url } = req.body || {};
  if (!url || !isValidUrl(url)) {
    return res.status(400).json({ error: "Please provide a valid video URL." });
  }

  execFile(
    "yt-dlp",
    ["-j", "--no-playlist", url],
    { maxBuffer: 1024 * 1024 * 20, timeout: 30000 },
    (err, stdout) => {
      if (err) {
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
app.get("/api/download", (req, res) => {
  const { url, format_id } = req.query;
  if (!url || !isValidUrl(url)) {
    return res.status(400).json({ error: "Invalid URL." });
  }

  const jobId = crypto.randomUUID();
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), `vdl-${jobId}-`));
  const outTemplate = path.join(outDir, "output.%(ext)s");

  const args = [
    "-o", outTemplate,
    "--no-playlist",
    "--no-part",
    "--merge-output-format", "mp4",
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
