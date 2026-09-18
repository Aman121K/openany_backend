FROM node:20-slim

# ffmpeg is needed to merge separate video/audio streams;
# curl + ca-certificates are needed to fetch the yt-dlp binary below.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install the yt-dlp standalone binary (bundles its own Python, no
# separate Python install needed).
RUN curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o /usr/local/bin/yt-dlp && \
    chmod a+rx /usr/local/bin/yt-dlp

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV PORT=5050
EXPOSE 5050

CMD ["node", "server.js"]
