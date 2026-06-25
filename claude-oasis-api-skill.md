# Claude Skill: PM Scrapbook API Access

Use this when Claude needs authenticated API access to the PM Scrapbook instance.

- Base URL: `https://pm-scrapbook-32343774681.us-central1.run.app`
- Auth: cookie-based session (not Bearer token)

## 1) Scripts location

Scripts are installed at:

- `~/.claude/skills/pm-scrapbook-api/scripts/`

## 2) Configure credentials

Create `~/.claude/secrets/pm-scrapbook-api-oasis/env`:

```bash
mkdir -p ~/.claude/secrets/pm-scrapbook-api-oasis
cat > ~/.claude/secrets/pm-scrapbook-api-oasis/env <<EOF
PM_SCRAPBOOK_BASE_URL=https://pm-scrapbook-32343774681.us-central1.run.app
PM_SCRAPBOOK_EMAIL=shivani@appsecure.ai
PM_SCRAPBOOK_PASSWORD=<password>
EOF
chmod 600 ~/.claude/secrets/pm-scrapbook-api-oasis/env
```

## 3) Bootstrap/check auth

```bash
export PM_SCRAPBOOK_AUTH_DIR="$HOME/.claude/secrets/pm-scrapbook-api-oasis"

~/.claude/skills/pm-scrapbook-api/scripts/ensure_pm_scrapbook_auth.sh --check-only || \
~/.claude/skills/pm-scrapbook-api/scripts/ensure_pm_scrapbook_auth.sh
```

## 4) Call API

```bash
export PM_SCRAPBOOK_AUTH_DIR="$HOME/.claude/secrets/pm-scrapbook-api-oasis"

~/.claude/skills/pm-scrapbook-api/scripts/pm_scrapbook_api.sh get /api/auth/session
~/.claude/skills/pm-scrapbook-api/scripts/pm_scrapbook_api.sh get '/api/pm/backlog-items?limit=20&include_archived=true'
~/.claude/skills/pm-scrapbook-api/scripts/pm_scrapbook_api.sh patch /api/pm/backlog-items/320 '{"status":"planned"}'
```
