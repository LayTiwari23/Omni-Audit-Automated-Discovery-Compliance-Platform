# ==============================================================================
#  Frontend Container – two‑stage build
# ==============================================================================

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=${VITE_API_URL}

COPY package.json package-lock.json* ./
RUN npm ci --frozen-lockfile

COPY . .
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine

# Install curl for healthcheck
RUN apk add --no-cache curl

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY certs /etc/nginx/certs

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -k -f https://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
