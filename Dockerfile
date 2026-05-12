FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY src/ ./src/
COPY .env* ./

EXPOSE 8080

CMD ["node", "--require", "./src/telemetry-init.cjs", "src/start.js"]
