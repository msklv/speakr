###############################################################################
# Stage 1: Builder — install Python deps and download vendor assets
###############################################################################
FROM python:3.11-slim AS builder

ARG PRODUCTION=0
ARG LIGHTWEIGHT=0

WORKDIR /app

# gcc is needed to compile C extensions during pip install
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt requirements-embeddings.txt constraints.txt ./
RUN pip install --no-cache-dir --prefix=/install -c constraints.txt -r requirements.txt && \
    if [ "$LIGHTWEIGHT" = "0" ]; then \
        pip install --no-cache-dir --prefix=/install -c constraints.txt -r requirements-embeddings.txt; \
    fi && \
    find /install -name "examples-1.json" -delete && \
    rm -rf /install/lib/python3.11/site-packages/boto3/examples
# KCS: fake AWS keys ("AKIAIO...MPLE") ship inside boto3/botocore doc examples.
# They must be removed HERE (builder) so COPY --from=builder never puts them
# into a final-image layer: KCS scans secret rules against raw layer tarballs,
# so a delete in the runtime stage leaves the blobs scannable even though the
# merged rootfs is clean (observed on fix5: 2 crit + 2 high still flagged).

# Download vendor assets (JS/CSS/fonts)
RUN mkdir -p /app/static/vendor
COPY scripts/download_offline_deps.py scripts/
RUN pip install --no-cache-dir requests && \
    PRODUCTION=${PRODUCTION} python scripts/download_offline_deps.py && \
    echo "✓ Vendor dependencies downloaded successfully"

###############################################################################
# Stage 2: FFmpeg — download static binaries (much smaller than apt ffmpeg)
#
# Source: BtbN/FFmpeg-Builds. We moved off the johnvansickle static builds
# because that mirror is frozen at 7.0.2 (2024) and therefore ships the MagicYUV
# decoder flaw CVE-2026-8461 ("PixelSmash", heap out-of-bounds write, RCE via
# crafted media), fixed upstream in 8.1.2.
#
# Supply-chain hardening: we pin a dated release (not BtbN's rolling `latest`
# tag) and verify each arch tarball's SHA-256, so a swapped or tampered binary
# fails the build. NOTE: BtbN deletes autobuild assets after roughly two weeks,
# so any rebuild after that window fails with a wget 404 until the pin is
# refreshed. To refresh, bump BTBN_TAG, FFMPEG_VER and BOTH checksums together
# (read the new values from the release's checksums.sha256). BtbN binaries nest
# under bin/, hence the adjusted move paths.
###############################################################################
FROM python:3.11-slim AS ffmpeg-stage

ARG BTBN_TAG=autobuild-2026-08-30-13-12
ARG FFMPEG_VER=n8.1.2-50-g1a748fe2cd
ARG FFMPEG_SHA256_amd64=ea0aa14aa7a45bba0825616c5b2a1c331d8ca19dff4fa51f941587fc16affb27
ARG FFMPEG_SHA256_arm64=df7ae09ed730f62051ff239e836061c976134d06b04b8ad054b3796fead4bb6f

RUN apt-get update && apt-get install -y --no-install-recommends wget xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && case "$(dpkg --print-architecture)" in \
         amd64) BTBN_ARCH=linux64;    SHA256="${FFMPEG_SHA256_amd64}" ;; \
         arm64) BTBN_ARCH=linuxarm64; SHA256="${FFMPEG_SHA256_arm64}" ;; \
         *) echo "Unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
       esac \
    && ASSET="ffmpeg-${FFMPEG_VER}-${BTBN_ARCH}-gpl-8.1.tar.xz" \
    && wget -q "https://github.com/BtbN/FFmpeg-Builds/releases/download/${BTBN_TAG}/${ASSET}" -O /tmp/ff.tar.xz \
    && echo "${SHA256}  /tmp/ff.tar.xz" | sha256sum -c - \
    && mkdir -p /tmp/ffmpeg-dir \
    && tar xf /tmp/ff.tar.xz -C /tmp/ffmpeg-dir --strip-components=1 \
    && mv /tmp/ffmpeg-dir/bin/ffmpeg /usr/local/bin/ffmpeg \
    && mv /tmp/ffmpeg-dir/bin/ffprobe /usr/local/bin/ffprobe \
    && chmod +x /usr/local/bin/ffmpeg /usr/local/bin/ffprobe \
    && rm -rf /tmp/ff.tar.xz /tmp/ffmpeg-dir

###############################################################################
# Stage 3: Runtime — lean final image with only what's needed
###############################################################################
FROM python:3.11-slim

WORKDIR /app

# Copy static ffmpeg binaries (~150MB vs ~450MB from apt)
COPY --from=ffmpeg-stage /usr/local/bin/ffmpeg /usr/local/bin/ffmpeg
COPY --from=ffmpeg-stage /usr/local/bin/ffprobe /usr/local/bin/ffprobe

# Copy installed Python packages from builder
# (KCS: boto3/botocore doc examples with fake AWS keys are already stripped in
# the builder stage above — never here, so they never enter a final-image layer.)
COPY --from=builder /install /usr/local

# KCS hardening: purge perl-base (3 Criticals incl. exploited CVE-2026-8376,
# 5 Highs, no Debian fix available). dpkg reverse-deps on it are empty in this
# image and nothing in the runtime path calls perl: entrypoint is bash,
# update-ca-certificates is /bin/sh, ffmpeg/ffprobe are static binaries.
# It is an Essential package, hence --allow-remove-essential; the trade-off is
# that `apt install/upgrade` *inside a running container* may try to pull it
# back — we never run apt at runtime, so this is acceptable.
RUN apt-get purge --allow-remove-essential -y perl-base

# KCS hardening: purge the util-linux family + sqlite/ncurses/gzip leaves of
# the base image (42 of the 48 High findings; all fixedVersion:null upstream —
# nothing to upgrade TO). Verified in-container: apt resolves this group
# cleanly (individual purges break), 14 pkgs removed, dpkg --audit clean,
# bash/coreutils/dpkg/gunicorn all survive (their libs — libtinfo6,
# libsystemd0, libudev1, libacl1 — are deliberately kept). psycopg2/postgres
# path verified; `import sqlite3` FAILS after this — the -lite image is
# Postgres-only (see SQLALCHEMY_DATABASE_URI below).
RUN apt-get purge --allow-remove-essential -y \
        util-linux bsdutils mount login \
        libmount1 libblkid1 libuuid1 libsmartcols1 liblastlog2-2 \
        libsqlite3-0 libncursesw6 ncurses-base ncurses-bin gzip \
    && rm -rf /var/lib/apt/lists/*

# KCS hardening: bump base setuptools (79.0.1) to 81.0.0. KCS flags the *vendored*
# wheel 0.45.1 / jaraco.context 5.3.0 dist-info inside setuptools/_vendor;
# 81.0.0 vendors wheel 0.46.3 + jaraco.context 6.1.0 (both >= the CVE fixes) and
# still ships pkg_resources, which numpy/sklearn/scipy/werkzeug/pytz/babel import.
# (setuptools' own CVE-2025-47273 is fixed at 78.1.1; 83.x would drop
# pkg_resources and break the app stack, hence the ceiling at 81.)
RUN pip install --no-cache-dir "setuptools==81.0.0"

# Copy downloaded vendor assets from builder
COPY --from=builder /app/static/vendor /app/static/vendor

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /data/uploads /data/instance && chmod 755 /data/uploads /data/instance

# KCS hardening: run as non-root (was 'Image user should not be root').
RUN useradd --system --create-home --home-dir /home/speakr --shell /usr/sbin/nologin speakr \
    && chown -R speakr:speakr /data \
    && chmod 755 /data

# Set environment variables
ENV FLASK_APP=src/app.py
ENV SQLALCHEMY_DATABASE_URI=sqlite:////data/instance/transcriptions.db
ENV UPLOAD_FOLDER=/data/uploads
ENV PYTHONPATH=/app
ENV HF_HOME=/data/instance/huggingface
ENV HOME=/home/speakr

# Add entrypoint script
COPY scripts/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Drop privileges: everything from here runs as the unprivileged user.
USER speakr

EXPOSE 8899

# KCS hardening: liveness check (no curl in slim -> lightweight urllib probe;
# the app redirects / to login, accept any HTTP response as "up").
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import urllib.request;from urllib.error import HTTPError\ntry: urllib.request.urlopen('http://127.0.0.1:8899/',timeout=5)\nexcept HTTPError: pass"]

ENTRYPOINT ["docker-entrypoint.sh"]
# Threaded workers: streaming responses (chat/Inquire SSE, audio/video range
# requests) hold a request slot for their duration; with sync workers 3 such
# streams made the whole app unresponsive (#374). gthread gives 3x8 = 24
# concurrent requests; the app is thread-tolerant (background job threads,
# SQLite WAL) and streams are I/O-bound.
CMD ["gunicorn", "--workers", "3", "--worker-class", "gthread", "--threads", "8", "--bind", "0.0.0.0:8899", "--timeout", "600", "src.app:app"]
