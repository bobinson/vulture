# Single-stage build (NIT #21 fix). Base image pinned by DIGEST so the
# verified license (Semgrep 1.84.0 = LGPL-2.1) and contents can't change
# under a re-pushed tag. The :1.84.0 tag is kept for human readability;
# Docker resolves the @sha256 digest (multi-arch index). On any version
# bump, update the digest AND re-verify Semgrep's upstream LICENSE.
FROM semgrep/semgrep:1.84.0@sha256:e792d418d128c4c7ea3842677192b7a06458747fbdbeda350a5cd2c7abbb7bbe
WORKDIR /app

# MINOR #15 fix: Semgrep's default rules cache lives under $HOME/.semgrep,
# which is /root for this image. After the USER drop below `nobody`
# cannot read /root. Redirect the cache to /srv/semgrep-rules (writable
# by nobody after chown), pre-warm under that path, then drop user.
ENV SEMGREP_RULES_CACHE=/srv/semgrep-rules
RUN mkdir -p /srv/semgrep-rules \
 && chown -R 65534:65534 /srv/semgrep-rules \
 && semgrep --config p/auto --quiet /tmp 2>/dev/null || true

COPY pyproject.toml /app/
COPY src/    /app/src/
COPY rules/  /app/rules/
RUN pip install --no-cache-dir fastapi "uvicorn[standard]"

EXPOSE 28011
# Explicit numeric uid for `nobody` avoids cross-distro variance (TM5).
USER 65534:65534
# Port 28011 avoids the very common host-side 8080 collision (catalyst,
# videogen, etc. are typical). For production/container-network
# deployments adjust the manifest's runtime.port to match.
CMD ["uvicorn", "src.wrapper:app", "--host", "0.0.0.0", "--port", "28011"]
