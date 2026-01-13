FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY . .

ENV PORT=5001
EXPOSE 5001

CMD ["node", "server.js"]
