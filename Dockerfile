# Stage 1: Build static production bundle (no source maps, no TypeScript source in final image)
FROM node:22-alpine AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src
ARG APP_VERSION=""
ENV VITE_APP_VERSION=${APP_VERSION}
RUN npm run build

# Stage 2: Serve static bundle with Nginx
FROM nginx:alpine AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]
