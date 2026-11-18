FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --registry=https://registry.npmjs.org
COPY scripts/ ./scripts/
COPY web/ ./web/
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM postgres:17-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tini ca-certificates libatomic1 && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home secretmanager && usermod -a -G secretmanager postgres
COPY --from=build /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY src/ ./src/
COPY scripts/entrypoint.sh /usr/local/bin/secretmanager-entrypoint
RUN chmod 0755 /usr/local/bin/secretmanager-entrypoint && mkdir -p /keys /run/postgresql && chown secretmanager:secretmanager /keys
ENV NODE_ENV=production PGHOST=/run/postgresql PGUSER=secretmanager PGDATABASE=secretmanager PORT=8080
VOLUME ["/var/lib/postgresql/data", "/keys", "/backups"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/secretmanager-entrypoint"]
