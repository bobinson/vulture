---
name: Bug Report
about: Report a bug to help improve Vulture
title: "[BUG] "
labels: bug
assignees: ""
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. Go to '...'
2. Click on '...'
3. Scroll down to '...'
4. See error

## Expected Behavior

A clear description of what you expected to happen.

## Actual Behavior

A clear description of what actually happened.

## Agent Type

Which audit agent is affected? (Select all that apply)

- [ ] Chaos Engineering
- [ ] OWASP
- [ ] SOC2
- [ ] CWE
- [ ] Go Backend
- [ ] Frontend
- [ ] CLI
- [ ] Not agent-specific

## Environment

- **OS**: [e.g., Ubuntu 22.04, macOS 14.2, Windows 11]
- **Docker version**: [e.g., 24.0.7]
- **Docker Compose version**: [e.g., 2.23.0]
- **Browser** (if frontend issue): [e.g., Chrome 120, Firefox 121]
- **Node.js version** (if frontend issue): [e.g., 20.10.0]
- **Go version** (if backend issue): [e.g., 1.24]
- **Python version** (if agent issue): [e.g., 3.12.1]
- **LLM provider**: [e.g., OpenAI, Ollama, LM Studio]
- **LLM model**: [e.g., gpt-4o, qwen3:1.7b]

## Log Output

<details>
<summary>Relevant log output</summary>

```
Paste relevant log output here.
Include logs from the affected service (backend, agent, frontend console).
```

</details>

## Configuration

<details>
<summary>Relevant environment variables (redact secrets)</summary>

```
VULTURE_USE_LLM=
VULTURE_LLM_MODEL=
VULTURE_LLM_CTX_SIZE=
VULTURE_LOCAL_MODE=
```

</details>

## Screenshots

If applicable, add screenshots to help explain the problem.

## Additional Context

Add any other context about the problem here. Include relevant SSE event types if the issue is related to streaming (`agent_start`, `thinking`, `finding`, `progress`, `result`, `agent_end`).
