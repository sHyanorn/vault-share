FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS web
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS server
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vaultd ./cmd/vaultd \
    && mkdir -p /out/data

# Static binary, no shell, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=server /out/vaultd /vaultd
COPY --from=server --chown=65532:65532 /out/data /data
COPY --from=web /src/dist /srv/web
ENV VAULT_LISTEN_ADDR=:8080 \
    VAULT_DATA_DIR=/data \
    VAULT_WEB_DIR=/srv/web
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/vaultd"]
