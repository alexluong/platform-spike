FROM node:24-alpine AS build
RUN npm i -g pnpm@12.11.2
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
RUN pnpm build

FROM node:24-alpine
RUN npm i -g pnpm@12.11.2
WORKDIR /app
ENV NODE_ENV=production
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prod && npm rm -g pnpm
COPY --from=build /app/dist ./dist
COPY drizzle ./drizzle
EXPOSE 8086
CMD ["node", "dist/main.js"]
