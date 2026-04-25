# CI Integration Guide

Integrate Vulture compliance audits into your CI/CD pipelines. CI runners act as thin clients (Mode D) that submit scan requests to a centralized Vulture server (Mode B). The CI runner never executes the backend, agents, or LLMs itself.

```
CI runner (ephemeral)                 Central server (persistent VM)
 vulture scan <git-url>  ──HTTPS──>   backend + agents + LLM
   --api-key X                          clones repo
   --wait                 <──SSE────    streams progress
   exit code 0 or 1                     persists findings to Neon
```

---

## Prerequisites

Before configuring CI, you need a running Vulture central server (Mode B). Follow [central_server_deployment.md](central_server_deployment.md) to provision the VM, configure the database, and bootstrap the admin user.

Once the server is running, you need:

1. The server's base URL (e.g. `https://vulture.example.com`)
2. An API key created via `vulture api-key create <name>`

---

## GitHub Actions

A ready-to-use workflow template is provided at `.github/workflow-examples/vulture-audit.yml`. Copy it into `.github/workflows/vulture-audit.yml` in any repository you want audited.

### Setting up secrets

1. Go to the target repository on GitHub.
2. Navigate to **Settings > Secrets and variables > Actions**.
3. Add two repository secrets:
   - `VULTURE_SERVER_URL` -- the base URL of your Vulture server (e.g. `https://vulture.example.com`)
   - `VULTURE_API_KEY` -- the API key from `vulture api-key create ci-github-actions`
4. `GITHUB_TOKEN` is provided automatically by GitHub Actions. It is used by the `--git-credentials` flag to allow the Vulture server to clone private repositories.

### Workflow overview

```yaml
name: Vulture Audit

on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Install Vulture CLI
        run: |
          curl -fsSL "${{ secrets.VULTURE_SERVER_URL }}/releases/latest/vulture-linux-amd64" \
            -o /usr/local/bin/vulture
          chmod +x /usr/local/bin/vulture
          vulture --version

      - name: Submit audit
        env:
          VULTURE_SERVER:   ${{ secrets.VULTURE_SERVER_URL }}
          VULTURE_API_KEY:  ${{ secrets.VULTURE_API_KEY }}
          GH_TOKEN:         ${{ secrets.GITHUB_TOKEN }}
        run: |
          vulture scan "${{ github.server_url }}/${{ github.repository }}.git" \
            --ref "${{ github.sha }}" \
            --server "$VULTURE_SERVER" \
            --api-key "$VULTURE_API_KEY" \
            --git-credentials "token:$GH_TOKEN" \
            --types cwe,owasp,do178c \
            --wait \
            --exit-on high \
            --output json > vulture-report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulture-report
          path: vulture-report.json
          retention-days: 30
```

The `--wait` flag causes the CLI to block until the audit completes (or the 15-minute timeout fires). The `--exit-on high` flag causes a non-zero exit if any finding at severity `high` or above is detected, failing the CI job.

---

## GitLab CI

Create `.gitlab-ci.yml` in your repository root:

```yaml
vulture-audit:
  stage: test
  image: ubuntu:24.04
  timeout: 15 minutes
  variables:
    VULTURE_SERVER: "$VULTURE_SERVER_URL"
    VULTURE_API_KEY: "$VULTURE_API_KEY"
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl > /dev/null
    - curl -fsSL "${VULTURE_SERVER}/releases/latest/vulture-linux-amd64"
        -o /usr/local/bin/vulture
    - chmod +x /usr/local/bin/vulture
    - vulture --version
  script:
    - |
      vulture scan "${CI_SERVER_URL}/${CI_PROJECT_PATH}.git" \
        --ref "$CI_COMMIT_SHA" \
        --server "$VULTURE_SERVER" \
        --api-key "$VULTURE_API_KEY" \
        --git-credentials "token:${CI_JOB_TOKEN}" \
        --types cwe,owasp,do178c \
        --wait \
        --exit-on high \
        --output json > vulture-report.json
  artifacts:
    when: always
    paths:
      - vulture-report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### GitLab secrets setup

1. Go to your project or group in GitLab.
2. Navigate to **Settings > CI/CD > Variables**.
3. Add two variables (mark both as **Masked** and optionally **Protected**):
   - `VULTURE_SERVER_URL` -- the base URL of your Vulture server
   - `VULTURE_API_KEY` -- the API key from `vulture api-key create ci-gitlab`
4. `CI_JOB_TOKEN` is provided automatically by GitLab and used for repository cloning.

---

## Jenkins

Create a declarative pipeline (e.g. in `Jenkinsfile`):

```groovy
pipeline {
    agent any
    options {
        timeout(time: 15, unit: 'MINUTES')
    }
    stages {
        stage('Install Vulture CLI') {
            steps {
                withCredentials([
                    string(credentialsId: 'vulture-server-url', variable: 'VULTURE_SERVER'),
                    string(credentialsId: 'vulture-api-key',    variable: 'VULTURE_API_KEY')
                ]) {
                    sh '''
                        curl -fsSL "${VULTURE_SERVER}/releases/latest/vulture-linux-amd64" \
                            -o /usr/local/bin/vulture
                        chmod +x /usr/local/bin/vulture
                        vulture --version
                    '''
                }
            }
        }
        stage('Submit Audit') {
            steps {
                withCredentials([
                    string(credentialsId: 'vulture-server-url', variable: 'VULTURE_SERVER'),
                    string(credentialsId: 'vulture-api-key',    variable: 'VULTURE_API_KEY'),
                    string(credentialsId: 'git-token',          variable: 'GIT_TOKEN')
                ]) {
                    sh '''
                        vulture scan "${GIT_URL}" \
                            --ref "${GIT_COMMIT}" \
                            --server "${VULTURE_SERVER}" \
                            --api-key "${VULTURE_API_KEY}" \
                            --git-credentials "token:${GIT_TOKEN}" \
                            --types cwe,owasp,do178c \
                            --wait \
                            --exit-on high \
                            --output json > vulture-report.json
                    '''
                }
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'vulture-report.json', allowEmptyArchive: true
        }
    }
}
```

### Jenkins credentials setup

1. Go to **Manage Jenkins > Manage Credentials**.
2. Add three **Secret text** credentials:
   - `vulture-server-url` -- the base URL of your Vulture server
   - `vulture-api-key` -- the API key from `vulture api-key create ci-jenkins`
   - `git-token` -- a personal access token or deploy key for cloning the repository
3. Reference them in `withCredentials` blocks as shown above.

---

## Authentication

### Creating API keys

API keys are created via the Vulture CLI by an authenticated admin user:

```bash
vulture api-key create ci-github-actions
# Output:
#   API Key created successfully.
#   Key: vk_a1b2c3d4e5f6g7h8i9j0...
#   SAVE THIS NOW -- you will not see it again.
#   Name:   ci-github-actions
#   Prefix: vk_a1b2c3
```

The full key (`vk_...`) is displayed exactly once. Copy it immediately into your CI system's secrets store.

### Listing and revoking keys

```bash
# List all API keys (shows prefix, name, last used -- never the full key)
vulture api-key list

# Revoke a specific key by its ID
vulture api-key revoke <key-id>
```

### Key rotation

Rotate API keys every 90 days. The procedure:

1. Create a new key: `vulture api-key create ci-github-actions-2026q3`
2. Update the CI secret (`VULTURE_API_KEY`) with the new key value.
3. Verify a CI run succeeds with the new key.
4. Revoke the old key: `vulture api-key revoke <old-key-id>`

Use separate keys per CI system (one for GitHub Actions, one for GitLab, one for Jenkins, etc.) so that revoking one does not disrupt others.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Audit completed successfully. No findings at or above the `--exit-on` severity threshold. |
| 1 | Audit completed. One or more findings at or above the `--exit-on` threshold were detected. |
| 2 | Audit execution error: network failure, authentication failure, LLM error, or server-side fault. |

When `--exit-on` is not specified, the CLI exits 0 on successful completion regardless of findings.

Severity levels from lowest to highest: `info`, `low`, `medium`, `high`, `critical`. Setting `--exit-on medium` will cause exit code 1 if any finding is `medium`, `high`, or `critical`.

---

## Output formats

### Text (default)

Human-readable output with color-coded severity. Suitable for terminal viewing and CI logs:

```bash
vulture scan <git-url> --server $VULTURE_SERVER --api-key $KEY --wait --output text
```

### JSON (machine-readable)

Structured output with the full finding list, scores, and metadata. Suitable for downstream tooling, dashboards, and artifact archival:

```bash
vulture scan <git-url> --server $VULTURE_SERVER --api-key $KEY --wait --output json > report.json
```

The JSON output contains:

```json
{
  "audit_id": "...",
  "status": "completed",
  "types": ["cwe", "owasp"],
  "scores": { "cwe": 72, "owasp": 85 },
  "findings": [
    {
      "severity": "high",
      "title": "SQL injection in query builder",
      "file_path": "src/db/query.go",
      "line": 42,
      "category": "CWE-89",
      "recommendation": "Use parameterized queries."
    }
  ],
  "summary": { "critical": 0, "high": 1, "medium": 3, "low": 5, "info": 2 }
}
```

---

## Webhook mode (fire-and-forget)

Instead of blocking with `--wait`, you can use `--webhook` to receive a callback when the audit completes. This is useful for long-running audits or when CI minutes are expensive.

```bash
vulture scan <git-url> \
  --server "$VULTURE_SERVER" \
  --api-key "$KEY" \
  --types cwe,owasp \
  --webhook "https://ci.example.com/hooks/vulture" \
  --output json
# Exits immediately with code 0 after the audit is accepted.
```

### Webhook payload

The server sends an HTTP POST to the webhook URL when the audit completes:

```json
{
  "event": "audit.completed",
  "audit_id": "abc123",
  "status": "completed",
  "scores": { "cwe": 72, "owasp": 85 },
  "summary": { "critical": 0, "high": 1, "medium": 3, "low": 5, "info": 2 },
  "server_url": "https://vulture.example.com",
  "results_url": "https://vulture.example.com/audits/abc123"
}
```

### HMAC signature verification

Every webhook delivery includes an `X-Vulture-Signature` header containing an HMAC-SHA256 signature computed over the raw request body using the `VULTURE_WEBHOOK_SECRET` configured on the server.

To verify:

```python
import hmac, hashlib

expected = hmac.new(
    webhook_secret.encode(),
    request.body,
    hashlib.sha256
).hexdigest()

received = request.headers["X-Vulture-Signature"].removeprefix("sha256=")
assert hmac.compare_digest(expected, received)
```

### Webhook retries

If the webhook URL returns a non-2xx status or the connection fails, the server retries up to 3 times with exponential backoff (10s, 60s, 300s). Delivery attempts are logged in the `audit_webhook_deliveries` table.

### Polling alternative

If webhooks are not feasible, poll the audit status endpoint instead:

```bash
# Submit without --wait or --webhook
AUDIT_ID=$(vulture scan <git-url> --server "$VULTURE_SERVER" --api-key "$KEY" --output json | jq -r '.audit_id')

# Poll until complete
while true; do
  STATUS=$(curl -s -H "Authorization: Bearer $KEY" "$VULTURE_SERVER/api/audits/$AUDIT_ID" | jq -r '.status')
  [ "$STATUS" = "completed" ] && break
  [ "$STATUS" = "failed" ] && exit 2
  sleep 10
done

# Fetch results
curl -s -H "Authorization: Bearer $KEY" "$VULTURE_SERVER/api/audits/$AUDIT_ID" > report.json
```

---

## Troubleshooting

### Authentication failures

**Symptom:** `401 Unauthorized` or `403 Forbidden` from the Vulture server.

**Causes:**
- The API key is incorrect or has been revoked. Verify with `vulture api-key list` on the server.
- `VULTURE_API_KEYS_ENABLED` is not set to `true` on the server. API key auth is opt-in.
- The key was copied with leading/trailing whitespace. Ensure the CI secret value is trimmed.

### Rate limits

The server enforces per-key rate limits to prevent runaway CI loops from exhausting LLM resources. Default: 60 requests per hour per key.

**Symptom:** `429 Too Many Requests`.

**Resolution:** Stagger CI jobs or request a higher limit from the server operator. Rate limits are configured on the server side.

### Webhook delivery failures

**Symptom:** Webhook never arrives after audit completion.

**Checklist:**
1. Verify the webhook URL is reachable from the server VM (not behind a firewall that blocks outbound requests).
2. Check delivery logs: query the `audit_webhook_deliveries` table or inspect server logs (`docker compose logs -f backend | grep webhook`).
3. Ensure `VULTURE_WEBHOOK_SECRET` is set on the server. Without it, webhook dispatch is disabled.
4. The webhook endpoint must return a 2xx status within 30 seconds. Timeouts count as failures and trigger retries.

### Connection timeouts

**Symptom:** CLI hangs or times out waiting for audit results.

**Causes:**
- The server is under heavy load. A single VM handles approximately 20-50 audits per day depending on codebase size and LLM model.
- The `--wait` timeout may be too short for large codebases. The default wait timeout is 10 minutes; the GitHub Actions example sets a 15-minute job timeout.
- Network issues between the CI runner and the server. Verify with `curl -s $VULTURE_SERVER/health`.

### Git clone failures on the server

**Symptom:** Audit fails with a git clone error.

**Causes:**
- The `--git-credentials` token has expired or lacks read access to the repository.
- The repository URL is incorrect (missing `.git` suffix for some hosts).
- The server VM cannot reach the git host (firewall, DNS).

---

## Security notes

1. **Never commit API keys** to source control. Always use your CI system's secrets management (GitHub Actions secrets, GitLab CI variables, Jenkins credentials).
2. **Rotate keys every 90 days.** Create new keys, swap them in CI, then revoke the old ones.
3. **Use separate keys per CI system.** If one system is compromised, revoke only that key without disrupting others.
4. **Git credentials are per-request and ephemeral.** The `--git-credentials` value is passed to the server for the duration of the clone, then discarded. It is never persisted to the database or written to logs.
5. **Webhook secrets** should be at least 32 bytes of random hex. Generate with `openssl rand -hex 32`.
6. **TLS is required** for production deployments. The central server should be behind a reverse proxy with a valid certificate. See [central_server_deployment.md](central_server_deployment.md) for TLS setup.
