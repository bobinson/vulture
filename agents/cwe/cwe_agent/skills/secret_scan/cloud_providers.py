"""Cloud / SaaS provider secret detection.

Detects content-pattern secrets for AWS, GCP, GitHub, GitLab, Stripe,
Slack, Twilio, SendGrid, Mailgun, Datadog, Heroku, Discord, Telegram,
Cloudflare, and JWT shapes.

CWE-798: Use of Hard-coded Credentials.
CWE-200: Information Exposure (for Twilio account SIDs and JWTs whose
payload is sensitive).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cwe_agent.skills.secret_scan import context as ctx


@dataclass(frozen=True)
class CloudPattern:
    """One provider-specific detection rule."""
    regex: re.Pattern[str]
    name: str
    cwe: str  # "798" / "200"
    severity: str  # critical / high / medium / low / info
    kind: str  # live / test / temp / id / info
    rule_id: str  # short stable name for the check_id suffix
    prefix_filter: str | None = None  # if set, file must contain this substring


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------
# Patterns derived from public references including gitleaks (MIT) and
# detect-secrets (Apache-2.0). The regex strings themselves are not
# copyrightable; we re-implement around them.

CLOUD_PATTERNS: list[CloudPattern] = [
    # ── AWS ──────────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        name="AWS Access Key ID",
        cwe="798", severity="critical", kind="live",
        rule_id="aws_access_key_id",
        prefix_filter="AKIA",
    ),
    CloudPattern(
        regex=re.compile(r"\bASIA[0-9A-Z]{16}\b"),
        name="AWS Temporary Access Key (STS)",
        cwe="798", severity="high", kind="temp",
        rule_id="aws_temp_access_key",
        prefix_filter="ASIA",
    ),
    # AWS secret access key — only flagged when "aws" appears on the
    # same line as the quoted 40-char base64-ish value. Allows
    # arbitrary chars between "aws" and the value (variable names like
    # AWS_SECRET_ACCESS_KEY have alphanumeric segments between).
    CloudPattern(
        regex=re.compile(
            r"(?i)aws[^\n]{0,60}['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        name="AWS Secret Access Key",
        cwe="798", severity="critical", kind="live",
        rule_id="aws_secret_access_key",
        prefix_filter="aws",
    ),

    # ── GitHub ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        name="GitHub Personal Access Token",
        cwe="798", severity="critical", kind="live",
        rule_id="github_pat",
        prefix_filter="ghp_",
    ),
    CloudPattern(
        regex=re.compile(r"\bghs_[A-Za-z0-9]{36}\b"),
        name="GitHub App / Server Token",
        cwe="798", severity="critical", kind="live",
        rule_id="github_app_token",
        prefix_filter="ghs_",
    ),
    CloudPattern(
        regex=re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        name="GitHub OAuth Access Token",
        cwe="798", severity="critical", kind="live",
        rule_id="github_oauth_token",
        prefix_filter="gho_",
    ),
    CloudPattern(
        regex=re.compile(r"\bghu_[A-Za-z0-9]{36}\b"),
        name="GitHub User-to-Server Token",
        cwe="798", severity="critical", kind="live",
        rule_id="github_user_to_server_token",
        prefix_filter="ghu_",
    ),
    CloudPattern(
        regex=re.compile(r"\bghr_[A-Za-z0-9]{36}\b"),
        name="GitHub Refresh Token",
        cwe="798", severity="critical", kind="live",
        rule_id="github_refresh_token",
        prefix_filter="ghr_",
    ),

    # ── GitLab ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
        name="GitLab PAT",
        cwe="798", severity="critical", kind="live",
        rule_id="gitlab_pat",
        prefix_filter="glpat-",
    ),

    # ── Stripe ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bsk_live_[A-Za-z0-9]{24,99}\b"),
        name="Stripe Live Secret Key",
        cwe="798", severity="critical", kind="live",
        rule_id="stripe_live_secret",
        prefix_filter="sk_live_",
    ),
    CloudPattern(
        regex=re.compile(r"\brk_live_[A-Za-z0-9]{24,99}\b"),
        name="Stripe Restricted Live Key",
        cwe="798", severity="critical", kind="live",
        rule_id="stripe_restricted_live",
        prefix_filter="rk_live_",
    ),
    CloudPattern(
        regex=re.compile(r"\bsk_test_[A-Za-z0-9]{24,99}\b"),
        name="Stripe Test Secret Key",
        cwe="798", severity="low", kind="test",
        rule_id="stripe_test_secret",
        prefix_filter="sk_test_",
    ),
    CloudPattern(
        regex=re.compile(r"\bpk_live_[A-Za-z0-9]{24,99}\b"),
        name="Stripe Publishable Live Key",
        cwe="200", severity="info", kind="info",
        rule_id="stripe_publishable_live",
        prefix_filter="pk_live_",
    ),

    # ── Slack ────────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(
            r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b"
        ),
        name="Slack Bot Token",
        cwe="798", severity="high", kind="live",
        rule_id="slack_bot_token",
        prefix_filter="xoxb-",
    ),
    CloudPattern(
        regex=re.compile(
            r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b"
        ),
        name="Slack User Token",
        cwe="798", severity="high", kind="live",
        rule_id="slack_user_token",
        prefix_filter="xoxp-",
    ),
    CloudPattern(
        regex=re.compile(r"\bxoxa-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b"),
        name="Slack Workspace Token",
        cwe="798", severity="high", kind="live",
        rule_id="slack_workspace_token",
        prefix_filter="xoxa-",
    ),
    CloudPattern(
        regex=re.compile(
            r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}\b"
        ),
        name="Slack Webhook URL",
        cwe="798", severity="high", kind="live",
        rule_id="slack_webhook",
        prefix_filter="hooks.slack.com",
    ),

    # ── Google ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        name="Google API Key",
        cwe="798", severity="critical", kind="live",
        rule_id="google_api_key",
        prefix_filter="AIza",
    ),
    CloudPattern(
        regex=re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{28}\b"),
        name="Google OAuth Client Secret",
        cwe="798", severity="critical", kind="live",
        rule_id="google_oauth_client_secret",
        prefix_filter="GOCSPX-",
    ),
    CloudPattern(
        regex=re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b"),
        name="Google OAuth Access Token",
        cwe="798", severity="critical", kind="live",
        rule_id="google_oauth_access_token",
        prefix_filter="ya29.",
    ),

    # ── Twilio ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bAC[a-f0-9]{32}\b"),
        name="Twilio Account SID",
        cwe="200", severity="medium", kind="id",
        rule_id="twilio_account_sid",
        prefix_filter="AC",
    ),
    CloudPattern(
        regex=re.compile(r"\bSK[a-f0-9]{32}\b"),
        name="Twilio API Key SID",
        cwe="798", severity="high", kind="live",
        rule_id="twilio_api_key_sid",
        prefix_filter="SK",
    ),

    # ── SendGrid ─────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        name="SendGrid API Key",
        cwe="798", severity="critical", kind="live",
        rule_id="sendgrid_api_key",
        prefix_filter="SG.",
    ),

    # ── Mailgun ──────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bkey-[a-f0-9]{32}\b"),
        name="Mailgun API Key",
        cwe="798", severity="high", kind="live",
        rule_id="mailgun_api_key",
        prefix_filter="key-",
    ),

    # ── Datadog ──────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"(?i)\bdd_(?:api|app)_key\s*[=:]\s*['\"]([a-f0-9]{32})['\"]"),
        name="Datadog API/APP Key",
        cwe="798", severity="high", kind="live",
        rule_id="datadog_api_key",
        prefix_filter="dd_",
    ),

    # ── Heroku ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(
            r"(?i)heroku[\s\-_.]*(?:api[\s\-_.]*)?key\s*[=:]\s*['\"]"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"
        ),
        name="Heroku API Key",
        cwe="798", severity="high", kind="live",
        rule_id="heroku_api_key",
        prefix_filter="heroku",
    ),

    # ── Discord ──────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(
            r"\b(?:N|M|O)[A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b"
        ),
        name="Discord Bot Token",
        cwe="798", severity="high", kind="live",
        rule_id="discord_bot_token",
        prefix_filter=None,  # too short to be selective
    ),
    CloudPattern(
        regex=re.compile(
            r"\bhttps://discord\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,80}\b"
        ),
        name="Discord Webhook URL",
        cwe="798", severity="high", kind="live",
        rule_id="discord_webhook",
        prefix_filter="discord.com/api/webhooks",
    ),

    # ── Telegram ─────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"),
        name="Telegram Bot Token",
        cwe="798", severity="high", kind="live",
        rule_id="telegram_bot_token",
        prefix_filter=None,
    ),

    # ── Cloudflare ───────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(
            r"(?i)cloudflare[\s\-_.]*(?:api|global)?[\s\-_.]*key\s*[=:]\s*['\"]([a-f0-9]{37})['\"]"
        ),
        name="Cloudflare Global API Key",
        cwe="798", severity="critical", kind="live",
        rule_id="cloudflare_api_key",
        prefix_filter="cloudflare",
    ),

    # ── JWT ──────────────────────────────────────────────────────────
    # JWTs aren't always secret (the public claim format is by design),
    # but a checked-in JWT often signals a leaked session token.
    CloudPattern(
        regex=re.compile(
            r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,}\b"
        ),
        name="JSON Web Token",
        cwe="200", severity="medium", kind="info",
        rule_id="jwt",
        prefix_filter="eyJ",
    ),

    # ── npm token ────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        name="npm Access Token",
        cwe="798", severity="critical", kind="live",
        rule_id="npm_token",
        prefix_filter="npm_",
    ),

    # ── PyPI token ───────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
        name="PyPI API Token",
        cwe="798", severity="critical", kind="live",
        rule_id="pypi_token",
        prefix_filter="pypi-",
    ),

    # ── Square ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43}\b"),
        name="Square API Token",
        cwe="798", severity="critical", kind="live",
        rule_id="square_token",
        prefix_filter="sq0",
    ),

    # ── DigitalOcean ─────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        name="DigitalOcean Personal Access Token",
        cwe="798", severity="critical", kind="live",
        rule_id="digitalocean_pat",
        prefix_filter="dop_v1_",
    ),

    # ── Linear ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),
        name="Linear API Key",
        cwe="798", severity="high", kind="live",
        rule_id="linear_api_key",
        prefix_filter="lin_api_",
    ),

    # ── Notion ───────────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bsecret_[A-Za-z0-9]{43}\b"),
        name="Notion Integration Token",
        cwe="798", severity="high", kind="live",
        rule_id="notion_token",
        prefix_filter="secret_",
    ),

    # ── Anthropic / OpenAI ───────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{86,108}\b"),
        name="Anthropic API Key",
        cwe="798", severity="critical", kind="live",
        rule_id="anthropic_api_key",
        prefix_filter="sk-ant-",
    ),
    CloudPattern(
        regex=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,200}\b"),
        name="OpenAI API Key",
        cwe="798", severity="critical", kind="live",
        rule_id="openai_api_key",
        prefix_filter="sk-",
    ),

    # ── Hugging Face ─────────────────────────────────────────────────
    CloudPattern(
        regex=re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
        name="Hugging Face Access Token",
        cwe="798", severity="high", kind="live",
        rule_id="huggingface_token",
        prefix_filter="hf_",
    ),
]


def _split_lines_with_offsets(content: str) -> list[tuple[int, str]]:
    """Return ``[(line_num, line_text), ...]`` for each line in content."""
    return list(enumerate(content.splitlines(), start=1))


def find_cloud_secrets(file_path: Path, content: str) -> list[dict]:
    """Scan content for any cloud / SaaS provider secret pattern.

    Hot-path optimisation: each pattern declares an optional
    ``prefix_filter`` substring; if the file content doesn't contain
    that substring, the pattern's regex is skipped entirely. On a
    typical 1 KB source file this drops the regex evaluation count from
    ~30+ to ~2-3.
    """
    findings: list[dict] = []
    lines = _split_lines_with_offsets(content)
    content_lower = content.lower()

    for pattern in CLOUD_PATTERNS:
        # Pre-filter: if a prefix is declared and isn't in the content,
        # don't even compile/run the regex. The check is case-insensitive
        # so prefixes like "aws" match "AWS_SECRET_ACCESS_KEY".
        if pattern.prefix_filter and pattern.prefix_filter.lower() not in content_lower:
            continue

        for match in pattern.regex.finditer(content):
            # Find the line number containing the match start.
            line_num = content.count("\n", 0, match.start()) + 1
            line_text = lines[line_num - 1][1] if line_num <= len(lines) else ""

            # Skip placeholder-shaped values via the line context.
            if ctx.is_safe_context_line(line_text):
                continue

            findings.append({
                "severity": pattern.severity,
                "check_id": f"cwe.secret_scan.cloud.{pattern.rule_id}",
                "category": f"CWE-{pattern.cwe}",
                "title": f"Hardcoded {pattern.name}",
                "description": (
                    f"{pattern.name} pattern detected at line {line_num}. "
                    f"Hardcoded credentials must never be committed to source."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Remove the credential from source. Use a secrets manager "
                    "(Vault, AWS Secrets Manager, GCP Secret Manager) or "
                    "environment variables loaded at runtime. If this credential "
                    "was committed publicly, rotate it immediately."
                ),
                "code_snippet": _redact(line_text, match.group(0)),
                "kind": pattern.kind,
            })

    return findings


def _redact(line: str, secret: str) -> str:
    """Return ``line`` with ``secret`` replaced by a redacted marker.
    Keeps enough context for the operator to find the line without
    leaking the raw secret into logs / DB / API responses."""
    if not secret or len(secret) < 8:
        return line
    visible = secret[:4]
    return line.replace(secret, f"{visible}…[REDACTED]")
