# Membership Management System (PHP/MySQL)

> A deliberately vulnerable PHP application for security testing and research.

Dockerized membership management system from [CodeAstro](https://codeastro.com/download/membership-management-system-project-in-php-mysql-with-source-code/) — one command to deploy, ready for automated penetration testing with [Shannon](https://github.com/KeygraphHQ/shannon).

## Quick Start

```bash
git clone https://github.com/samhsu-dev/membership-management-php.git
cd membership-management-php
docker compose up -d --build
```

The application is available at **http://localhost:9010**.

| Field    | Value          |
|----------|----------------|
| Email    | admin@mail.com |
| Password | codeastro.com  |

## Security Testing with Shannon

[Shannon](https://github.com/KeygraphHQ/shannon) is an autonomous AI pentester that analyzes source code and executes real exploits against a running target. It requires **Docker**, **Node.js 18+**, and an LLM API key.

### Option A: OpenAI API

```bash
# 1. Configure Shannon
cat > ~/.shannon/config.toml << 'EOF'
[router]
openai_key = "sk-YOUR-OPENAI-API-KEY"
default = "openai,gpt-4.1"
EOF
chmod 600 ~/.shannon/config.toml

# 2. Make sure the target app is running
docker compose up -d --build

# 3. Start the pentest
npx @keygraph/shannon start \
  -u http://host.docker.internal:9010 \
  -r "$(pwd)" \
  -w membership-pentest \
  --router
```

### Option B: OpenRouter

```bash
cat > ~/.shannon/config.toml << 'EOF'
[router]
openrouter_key = "sk-or-YOUR-OPENROUTER-KEY"
default = "openrouter,anthropic/claude-sonnet-4"
EOF
chmod 600 ~/.shannon/config.toml

npx @keygraph/shannon start \
  -u http://host.docker.internal:9010 \
  -r "$(pwd)" \
  -w membership-pentest \
  --router
```

### Option C: Anthropic API (Direct)

```bash
cat > ~/.shannon/config.toml << 'EOF'
[anthropic]
api_key = "sk-ant-YOUR-ANTHROPIC-KEY"
EOF
chmod 600 ~/.shannon/config.toml

npx @keygraph/shannon start \
  -u http://host.docker.internal:9010 \
  -r "$(pwd)" \
  -w membership-pentest
```

### Option D: Custom Proxy (LiteLLM / AWS Bedrock)

```bash
cat > ~/.shannon/config.toml << 'EOF'
[custom_base_url]
base_url = "http://host.docker.internal:4000"
auth_token = "sk-litellm-local"

[models]
small = "claude-haiku-4.5"
medium = "claude-sonnet-4.6"
large = "claude-sonnet-4.6"
EOF
chmod 600 ~/.shannon/config.toml

# Important: unset conflicting env vars if present
env -u CLAUDE_CODE_USE_BEDROCK -u AWS_REGION -u ANTHROPIC_API_KEY \
  npx @keygraph/shannon start \
    -u http://host.docker.internal:9010 \
    -r "$(pwd)" \
    -w membership-pentest
```

Model names in `[models]` must match exactly what `curl localhost:4000/v1/models` returns.

### Monitoring

```bash
# Tail live logs
npx @keygraph/shannon logs membership-pentest

# Temporal Web UI
open http://localhost:8233

# Check status
npx @keygraph/shannon status
```

### Reports

Shannon produces a comprehensive security assessment report after completing all five phases (Pre-Recon → Recon → Vulnerability Analysis → Exploitation → Reporting).

```bash
# Final report
cat ~/.shannon/workspaces/membership-pentest/deliverables/comprehensive_security_assessment_report.md

# Run metrics
cat ~/.shannon/workspaces/membership-pentest/session.json
```

### Cleanup

```bash
# Stop Shannon infrastructure
docker stop shannon-temporal && docker rm shannon-temporal
docker volume rm infra_temporal-data
docker network rm shannon-net

# Stop the target application
docker compose down -v
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Multiple providers detected` | Env var `CLAUDE_CODE_USE_BEDROCK=1` conflicts with config | `unset CLAUDE_CODE_USE_BEDROCK` or use `env -u` |
| `preflight failed AuthenticationError` | Model ID mismatch between config and proxy | Check `[models]` against `curl <proxy>/v1/models` |
| `Insecure permissions` | config.toml readable by others | `chmod 600 ~/.shannon/config.toml` |
| `Unknown section` | Invalid TOML section name | Valid: `anthropic`, `bedrock`, `vertex`, `custom_base_url`, `router`, `models`, `core` |
| Only one provider allowed | Multiple provider sections in config | Keep only one of `[anthropic]` / `[custom_base_url]` / `[bedrock]` / `[vertex]` / `[router]` |

## Project Structure

```
├── includes/           # PHP config, header, footer, sidebar, nav
├── plugins/            # AdminLTE, jQuery, Bootstrap, DataTables
├── dist/               # CSS/JS assets
├── uploads/            # Member photos and logo
├── DATABASE FILE/      # Original SQL dump
├── docker/mysql/       # Docker init SQL
├── Dockerfile          # PHP 7.4 + Apache + mysqli
├── docker-compose.yml  # PHP + MySQL 8.4, one-click startup
└── *.php               # Application pages (20 files)
```

## License

Original source by [CodeAstro](https://codeastro.com). Docker configuration added for research purposes.
