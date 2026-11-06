FROM node:26.12.1-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS web
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27.3-alpine@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS server
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
