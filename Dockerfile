# ADSEC - plateforme d'audit/pentest Active Directory (safe-by-default)
#
# Image d'execution minimale : installe le paquet depuis les sources,
# tourne en utilisateur non-root, et persiste ses donnees dans un volume
# monte sur /data (ADSEC_DATA_DIR).

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY adsec ./adsec

RUN pip install --no-cache-dir build && \
    python -m build --wheel -o /build/dist

FROM python:3.12-slim

LABEL org.opencontainers.image.title="adsec" \
      org.opencontainers.image.description="Plateforme d'audit et de pentest Active Directory (safe-by-default)"

# libkrb5 est necessaire a impacket pour l'authentification Kerberos (SMB).
RUN apt-get update && \
    apt-get install -y --no-install-recommends libkrb5-3 libkrb5support0 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin adsec

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

ENV ADSEC_DATA_DIR=/data \
    ADSEC_LOG_FORMAT=json \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
USER adsec
WORKDIR /home/adsec

ENTRYPOINT ["adsec"]
CMD ["--help"]
