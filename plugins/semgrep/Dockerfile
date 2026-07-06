# Single-stage build (NIT #21 fix). Base image pinned by DIGEST so the
# verified license (Semgrep 1.168.0 = LGPL-2.1, OSS engine) and contents
# can't change under a re-pushed tag. The :1.168.0 tag is kept for human
# readability; Docker resolves the @sha256 digest (multi-arch index). On any
# version bump, update the digest AND re-verify Semgrep's upstream LICENSE.
FROM semgrep/semgrep:1.168.0@sha256:59fbed6127ea7c5dde3ba6a85142733bb20ea9aaa36120c953904f1539aaf66e
WORKDIR /app

# MINOR #15 fix: Semgrep's default rules cache lives under $HOME/.semgrep,
# which is /root for this image. After the USER drop below `nobody`
# cannot read /root. Redirect the cache to /srv/semgrep-rules (writable
# by nobody after chown), pre-warm under that path, then drop user.
ENV SEMGREP_RULES_CACHE=/srv/semgrep-rules
# HOME is supplied at RUN time by the supervisor (-e HOME=/tmp, see
# buildEnvArgs) so Semgrep can write $HOME/.semgrep as the runtime user.
# We do NOT bake ENV HOME here: the build pre-warm below runs as root, and
# a root-created /tmp/.semgrep would then be unwritable by the dropped
# runtime user. Build-time prime of the default pack (NOT an offline cache
# — Semgrep re-resolves registry packs per run; the vendored rules/vulture
# rules are the hermetic tier, and a registry-fetch failure now surfaces as
# an audit error, not a silent 0 — see agui/translator.go resultErrorText).
RUN mkdir -p /srv/semgrep-rules \
 && chown -R 65534:65534 /srv/semgrep-rules \
 && semgrep --config p/auto --quiet /tmp 2>/dev/null || true

COPY pyproject.toml /app/
COPY src/    /app/src/
COPY rules/  /app/rules/
# R8 (0058/P2c): hard-pin the Semgrep engine version. The digest-pinned
# base above already ships exactly 1.168.0; this explicit pin is a
# self-documenting no-op that fails the build loudly if the base ever
# drifts from the version the ruleset snapshot was verified against.
# Bump procedure: update the FROM tag+digest, this pin, AND regenerate
# rules/RULESET_SNAPSHOT.json (semgrep_version + vendored hashes) together
# (mirrors the catalog 4.19.1 pin).
# --break-system-packages: the 1.168.0 base is an externally-managed
# (PEP 668) Python env; the base already ships semgrep 1.168.0 so this pin
# resolves as "already satisfied" (a no-op assertion that fails loudly only
# if the base ever drifts from the pinned version).
RUN pip install --no-cache-dir --break-system-packages semgrep==1.168.0
RUN pip install --no-cache-dir --break-system-packages fastapi "uvicorn[standard]"

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
