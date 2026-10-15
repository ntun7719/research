FROM ghcr.io/fatedier/frpc:v0.61.1 AS frpc

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Lattice DNS (Gemini Edition)" \
      org.opencontainers.image.description="DNS over TLS control plane with Android Private DNS pipelining, policy profiles, encrypted routing and FRP edge transport" \
      org.opencontainers.image.source="https://github.com/ntun7719/research"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-cryptography \
    unbound \
    unbound-anchor \
    dns-root-data \
    ca-certificates \
    certbot \
    python3-certbot-dns-cloudflare \
    openssl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home lattice \
    && mkdir -p /data \
    && chown 10001:10001 /data

COPY --from=frpc /usr/bin/frpc /usr/local/bin/frpc

WORKDIR /app
COPY --chown=10001:10001 lattice/ /app/lattice/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin" \
    DATA_DIR=/data

EXPOSE 8080 8853

HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).read()" || exit 1

ENTRYPOINT ["/usr/bin/tini","--","python3","-m","lattice.bootstrap"]
CMD ["python3","-m","lattice"]
