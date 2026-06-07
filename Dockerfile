FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# App source.
COPY server.js ./
COPY public ./public

ENV PORT=3000 DATA_DIR=/data
EXPOSE 3000
VOLUME ["/data"]

CMD ["node", "server.js"]
