# syntax=docker/dockerfile:1.10
FROM node:24.5.0-alpine3.22@sha256:e8e882c692a08878d55ec8ff6c5a4a71b3edca25eda0af4406e2a160d8a93cf2 AS build
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@10.25.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/console/package.json apps/console/package.json
RUN pnpm install --frozen-lockfile
COPY apps/console apps/console
RUN pnpm --dir apps/console build

FROM node:24.5.0-alpine3.22@sha256:e8e882c692a08878d55ec8ff6c5a4a71b3edca25eda0af4406e2a160d8a93cf2
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=build /workspace/apps/console/dist ./dist
COPY apps/console/server.mjs ./server.mjs
USER node
EXPOSE 8080
CMD ["node", "server.mjs"]
