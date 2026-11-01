# Single-stage build (NIT #21 fix). The backend builds this image on the
# user's machine and it is never published (feature 0102). The base is the
# official Python image (the wrapper's runtime); the engine is Opengrep
# (LGPL-2.1), downloaded below from Opengrep's own release and checked against
# a pinned sha256, so Vulture redistributes neither. Nothing of Semgrep's (its
# image, packages, rules or binaries) is used.
#
# Engine bump: pick the release, verify each asset's keyless signature once,
#   cosign verify-blob <asset> --signature <asset>.sig --certificate <asset>.cert \
#     --certificate-identity https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v<version> \
#     --certificate-oidc-issuer https://token.actions.githubusercontent.com
# then pin OPENGREP_VERSION and both sha256 values below. Base bump: update the
# tag and its index digest together.
FROM python:3.12.16-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
WORKDIR /app

# HOME is supplied at run time by the supervisor (-e HOME=/tmp, see
# buildEnvArgs) so the engine can write its settings as the runtime user.

# Opengrep 1.x is a self-extracting binary that unpacks into /tmp on each run.
# The download fails closed on an unknown architecture or a digest mismatch.
RUN set -eu; \
    OPENGREP_VERSION=1.33.1; \
    case "$(dpkg --print-architecture)" in \
      amd64) asset=opengrep_manylinux_x86; sha=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808;; \
      arm64) asset=opengrep_manylinux_aarch64; sha=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf;; \
      *) echo "opengrep: unsupported architecture $(dpkg --print-architecture)" >&2; exit 1;; \
    esac; \
    python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}" /usr/local/bin/opengrep; \
    echo "${sha}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/opengrep

# The wrapper's packages, every one pinned with its hashes (requirements.in
# names the two direct dependencies; requirements.txt is the uv lock).
COPY requirements.txt /app/
RUN pip install --no-cache-dir --retries 10 --timeout 60 --require-hashes -r /app/requirements.txt

COPY pyproject.toml /app/
COPY src/    /app/src/
COPY rules/  /app/rules/

# The build fails here if the engine cannot start.
RUN HOME=/tmp/engine-check opengrep --version >/dev/null \
 && rm -rf /tmp/engine-check

EXPOSE 28011
# Explicit numeric uid for `nobody` avoids cross-distro variance (TM5).
USER 65534:65534
# Port 28011 avoids the very common host-side 8080 collision (catalyst,
# videogen, etc. are typical). For production/container-network
# deployments adjust the manifest's runtime.port to match.
# S2 (0058 audit): honor VULTURE_BIND_HOST so the supervisor can force a
# loopback bind for host-network runs (default 0.0.0.0 for bridge/compose,
# where cross-container reachability is required). `exec` keeps uvicorn as
# PID 1 for correct signal handling.
CMD ["sh", "-c", "exec uvicorn src.wrapper:app --host ${VULTURE_BIND_HOST:-0.0.0.0} --port 28011"]
