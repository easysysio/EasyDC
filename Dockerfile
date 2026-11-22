# syntax=docker/dockerfile:1
# EasyDC container image.
#
#   docker build -t easydc .                  build from source (any machine)
#   docker build --target release ...          pack the release binaries in dist/
#
# The release workflow uses the second form: it already builds a static musl
# binary per architecture, so the image only copies it in, as
# dist/linux-<arch>/easydc. Both forms end in the same runtime stage.
#
# EasyDC keeps everything in one SQLite file, easydc.db, created in its working
# directory: here /data, a volume. It holds the bind password of every domain
# controller added, so /data is 0700 and the service runs as its own user, as
# the deb and rpm packages do.

# ── build from source ────────────────────────────────────────────────────────
FROM rust:1.100-alpine3.23 AS build
# perl and make build the vendored OpenSSL; musl-dev links the static binary.
RUN apk add --no-cache musl-dev perl make
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    CARGO_PROFILE_RELEASE_STRIP=true cargo build --release --locked \
    && cp target/release/EasyDC /easydc

# ── runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.24 AS runtime
# ca-certificates: the trust store for ldaps:// with certificate checks on.
# Mount the domain's CA and point SSL_CERT_FILE at it to trust Samba's own
# certificate (see the installation guide).
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 easydc \
    && adduser -S -D -H -u 10001 -G easydc -h /data easydc \
    && mkdir -p /data \
    && chown easydc:easydc /data \
    && chmod 0700 /data
WORKDIR /data
VOLUME /data
ENV EASYDC_PORT=3000
EXPOSE 3000
USER easydc
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${EASYDC_PORT}/login" || exit 1
ENTRYPOINT ["/usr/bin/easydc"]

LABEL org.opencontainers.image.title="EasyDC" \
      org.opencontainers.image.description="Samba Active Directory management from the browser" \
      org.opencontainers.image.url="https://easydc.easysys.io" \
      org.opencontainers.image.documentation="https://easydc.easysys.io/install/#docker" \
      org.opencontainers.image.source="https://github.com/easysysio/EasyDC" \
      org.opencontainers.image.licenses="MIT"

# ── the release binaries, one per architecture ───────────────────────────────
FROM runtime AS release
ARG TARGETARCH
COPY --chmod=0755 dist/linux-${TARGETARCH}/easydc /usr/bin/easydc

# ── default: built from source ───────────────────────────────────────────────
FROM runtime
COPY --from=build /easydc /usr/bin/easydc
