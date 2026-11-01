# Single-stage build (NIT #21 fix). The backend builds this image on the
# user's machine and it is never published: the base image is Semgrep's own,
# pulled from Semgrep's registry by the user, and it carries Semgrep's engines
# (the LGPL-2.1 engine and a proprietary one), which Vulture must not
# redistribute (feature 0102). Base pinned by DIGEST so its contents can't
# change under a re-pushed tag; the :1.168.0 tag is kept for readability. On
# any version bump, update the digest AND re-verify Semgrep's upstream licence.
FROM semgrep/semgrep:1.168.0@sha256:59fbed6127ea7c5dde3ba6a85142733bb20ea9aaa36120c953904f1539aaf66e
WORKDIR /app

# HOME is supplied at run time by the supervisor (-e HOME=/tmp, see
# buildEnvArgs) so Semgrep can write $HOME/.semgrep as the runtime user. The
# build fetches no rules: the vendored rules/vulture set is copied below.

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
# The wrapper's server packages are pinned exactly and installed under a
# constraint of every package the base ships, so none can replace one Semgrep
# imports: unpinned, fastapi 0.162 lifted opentelemetry-api past the base's
# exporters and the 0.1.1 image's engine could not start.
RUN pip list --format=freeze > /tmp/base.txt \
 && pip install --no-cache-dir --break-system-packages -c /tmp/base.txt \
      semgrep==1.168.0 fastapi==0.139.0 "uvicorn[standard]==0.49.0" \
 && rm /tmp/base.txt
# The build fails here, before anything is pushed or signed, if the engine
# cannot start.
RUN HOME=/tmp/engine-check semgrep --version --disable-version-check >/dev/null \
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
