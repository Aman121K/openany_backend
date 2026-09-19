FROM node:20-slim

# ffmpeg is needed to merge separate video/audio streams;
# curl + ca-certificates are needed to fetch the yt-dlp binary below.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install the yt-dlp_linux standalone binary — this build bundles its own
# Python interpreter. (The plain "yt-dlp" release asset is a zipapp that
# needs a python3 executable on PATH, which this base image doesn't have.)
RUN curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_linux -o /usr/local/bin/yt-dlp && \
    chmod a+rx /usr/local/bin/yt-dlp

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV PORT=5050
EXPOSE 5050

CMD ["node", "server.js"]
