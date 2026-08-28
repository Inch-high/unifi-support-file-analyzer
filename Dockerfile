FROM python:3.12-slim

LABEL org.opencontainers.image.title="UniFi Support File Analyzer" \
      org.opencontainers.image.description="Reads a UniFi support file and explains what went wrong. Runs entirely on your own machine." \
      org.opencontainers.image.source="https://github.com/Inch-high/unifi-support-file-analyzer" \
      org.opencontainers.image.licenses="MIT"

# gosu is the only addition, and only so the entrypoint can prepare a mounted
# directory as root and then drop to an unprivileged user before the server
# starts. No compiler is installed: every dependency ships a wheel for both
# architectures this image is built for.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copied on its own, ahead of the application, so editing the analyzer does not
# reinstall the dependencies on every build.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer/ ./analyzer/
COPY static/ ./static/
COPY docker/ ./docker/
RUN chmod +x /app/docker/entrypoint.sh

# Fixed ids to begin with; PUID and PGID move them at start-up to match whoever
# owns a bind-mounted directory on the host.
RUN groupadd -g 1000 analyzer \
 && useradd -u 1000 -g 1000 -M -d /app -s /usr/sbin/nologin analyzer

ENV ANALYZER_DATA_DIR=/data \
    ANALYZER_IMPORT_DIR=/import \
    ANALYZER_CLEAR_ON_START=true \
    PORT=8077 \
    PUID=1000 \
    PGID=1000

RUN mkdir -p /data /import && chown analyzer:analyzer /data /import

VOLUME ["/data"]
EXPOSE 8077

# Cheap: listing bundles is a directory read. The start period covers the
# import of any support file waiting in /import, which is not.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8077') + '/api/bundles', timeout=4)" || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
