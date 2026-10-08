FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

COPY db.js index.js ./
COPY public ./public
COPY keys ./keys

ENV NODE_ENV=production
EXPOSE 3000

USER node
CMD ["node", "index.js"]
