# AutoSecure (fork)

Fork of [saldevsautosec/autosecure](https://github.com/saldevsautosec/autosecure) — maintained by [waitno01/autosecure](https://github.com/waitno01/autosecure).

Request-based Microsoft account securing for Discord, with a built-in SMTP server and web dashboard. No Selenium or Playwright.

---

## Fork changes

This fork adds fixes and features on top of upstream:

| Area | Change |
|------|--------|
| **Mail** | Built-in Discord webhook forwarding + OTP detection (no separate `smtp-discord` needed) |
| **Mail** | Optional playtime OTP bridge (`mail.otp_bridge_url` in config) |
| **Securing** | Failure DMs include security email, password, and recovery code when recovery already ran |
| **Securing** | Lock/suspended/phone-locked detection before and during secure (uses `/check locked` API) |
| **Securing** | Bedrock / Game Pass accounts without a Java profile handled without crashing |
| **Securing** | Safer embed building (missing subscription/cape fields, partial success embeds) |
| **Dashboard** | Delete accounts from list + database |
| **Ops** | PM2 `ecosystem.config.cjs` for bot, API, and web |
| **Ops** | `setup.sh` for venv, web build, and PM2 start |

### Recent updates (2026-07-16)

| Area | Change |
|------|--------|
| **Game Pass filter** | Rejects only **active** Xbox Game Pass / Ultimate. Expired, canceled, and Realms/M365 upsell noise no longer false-positive as Game Pass. |
| **Autobuy hold** | Default credit hold **12h**; **Client+** role hold **3h** (`client_plus_role_id` / `client_plus_pending_hours`). |
| **Hold checks** | Split schedule: security-email pullback every **1h** (masked GetCredentialType, no password/OTP); Microsoft lock check every **6h**. |
| **CatB / overprotective** | Xbox SSO `proofs/Verify?mpcxt=CATB` completes via security-email OTP (SendOtt → VerifyProof, often 2 rounds), then `proofs/remind` with **Looks good**. Fixes false “No Minecraft” when Skip loops. |
| **Cookies / canary** | `get_cookies` no longer crashes on missing `apiCanary` — securing continues into MC check instead of aborting mid-flow. |

Upstream Discord invite and original docs are not affiliated with this fork.

---

## Table of contents

- [Requirements](#requirements)
- [Setup (step by step)](#setup-step-by-step)
- [Example config files](#example-config-files)
- [Configuration reference](#configuration-reference)
- [Email & DNS](#email--dns)
- [Running with PM2](#running-with-pm2)
- [Web dashboard](#web-dashboard)
- [Bot commands](#bot-commands)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.12+ | Bot, API, securing logic, SMTP |
| Node.js | 20+ (22 recommended for web build) | Dashboard frontend |
| PM2 | latest | Process manager (`npm i -g pm2`) |
| Port 25 | open (inbound) | SMTP for security emails |
| Domain + DNS | MX + A for mail | Deliver Microsoft OTPs to your host |

---

## Setup (step by step)

### 1. Clone

```bash
git clone https://github.com/waitno01/sunnysecure.git
cd sunnysecure   # or autosecure — folder name from clone
```

### 2. Create configs from examples

```bash
cp config/config.json.example config/config.json
cp config/bot.json.example config/bot.json          # if missing
cp cloudflared.yml.example cloudflared.yml         # optional tunnel
cp ecosystem.config.cjs.example ecosystem.config.cjs  # optional; repo may already ship one
```

**Never commit** `config/config.json` (gitignored). It holds the bot token, webhooks, proxies, and wallet keys.

### 3. Discord bot

1. Open [Discord Developer Portal](https://discord.com/developers/applications) → **New Application** → **Bot**
2. Enable **all Privileged Gateway Intents**
3. OAuth2 → URL Generator: scopes `bot` + `applications.commands` → invite to your server
4. Copy the bot token into `config/config.json` → `tokens.bot_token`
5. Put your Discord user ID in `owners` (Developer Mode → Copy User ID)

### 4. Fill `config/config.json` (minimum)

| Field | What to set |
|-------|-------------|
| `owners` | Your Discord snowflake ID(s) |
| `tokens.bot_token` | Discord bot token |
| `domain` | Domain that receives security mail (must match MX) |
| `web.credentials.username` | Dashboard login user |
| `web.credentials.password` | Long random password (not the example placeholder) |
| `web.credentials.jwt_secret` | Long random string / 64 hex chars |
| `mail.discord_webhook_all` | Webhook for every inbound mail (optional but useful) |
| `mail.discord_webhook_otp` | Webhook when an OTP is detected |
| `discord.*_channel` | Channel IDs for logs / accounts / censored logs |

Optional later: `proxy` / `coldproxy`, Skytools/Donut API keys, autobuy + LTC wallet, OTP bridge URLs.

### 5. DNS for mail (required for securing)

In Cloudflare (or your DNS), **DNS only** (grey cloud) for mail:

| Type | Name | Value |
|------|------|-------|
| A | `mail` | Your VPS public IP |
| MX | `@` | `mail.yourdomain.com` (priority 10) |

Open **TCP 25** inbound on the VPS firewall. Only one process should listen on port 25 (`autosecure-bot`).

### 6. Install & build

```bash
# Python
python3.12 -m venv .venv          # or python3
.venv/bin/pip install -r requirements.txt

# Web dashboard
cd web && npm install && npm run build && cd ..
```

Or one-shot (creates `config.json` from the example if missing, then exits so you can edit it):

```bash
chmod +x setup.sh
./setup.sh
# edit config/config.json, then run ./setup.sh again
```

### 7. Start with PM2

```bash
pm2 start ecosystem.config.cjs
pm2 save
pm2 status
pm2 logs autosecure-bot
```

| Process | Port | Role |
|---------|------|------|
| `autosecure-bot` | 25 (SMTP) | Discord bot + mail |
| `autosecure-api` | 8000 (localhost) | FastAPI |
| `autosecure-web` | 3000 | Dashboard UI |

Dashboard: `http://YOUR_VPS_IP:3000` — log in with `web.credentials`.

### 8. Optional public HTTPS (Cloudflare Tunnel)

```bash
cp cloudflared.yml.example cloudflared.yml
# set tunnel id, credentials-file, hostname
cloudflared tunnel --config cloudflared.yml run
```

Update `CORS_ORIGINS` in `ecosystem.config.cjs` to include your public UI origin.

---

## Example config files

Shipped templates (safe to commit — placeholders only):

| File | Purpose |
|------|---------|
| [`config/config.json.example`](config/config.json.example) | Secrets + runtime settings → copy to `config/config.json` |
| [`config/bot.json.example`](config/bot.json.example) | Commands, embeds, presence → copy to `config/bot.json` if needed |
| [`cloudflared.yml.example`](cloudflared.yml.example) | Cloudflare Tunnel ingress |
| [`ecosystem.config.cjs.example`](ecosystem.config.cjs.example) | PM2 apps (bot / API / web) |

Minimal `config/config.json` shape:

```json
{
  "owners": [ YOUR_DISCORD_ID ],
  "tokens": {
    "bot_token": "YOUR_DISCORD_BOT_TOKEN",
    "skytools_key": "",
    "donut_key": ""
  },
  "discord": {
    "logs_channel": "",
    "accounts_channel": "",
    "censored_logs_channel": ""
  },
  "autosecure": {
    "replace_main_alias": true,
    "enable_2fa": false,
    "minecon_mode": false,
    "reject": {
      "family_locked": true,
      "gamepass": true,
      "underage": true,
      "min_age_years": 18,
      "require_primary_alias": true,
      "check_donutsmp_ban": true,
      "require_no_sms_proof": true,
      "nfa_name_patterns": true
    }
  },
  "web": {
    "credentials": {
      "username": "dashboard_admin",
      "password": "REPLACE_WITH_A_LONG_RANDOM_PASSWORD",
      "jwt_secret": "REPLACE_WITH_64_HEX_CHARS_OR_LONG_RANDOM_STRING"
    }
  },
  "domain": "yourdomain.com",
  "proxy": { "enabled": false, "proxies": [] },
  "mail": {
    "discord_webhook_all": "",
    "discord_webhook_otp": "",
    "otp_bridge_url": "",
    "otp_bridge_token": ""
  },
  "autobuy": {
    "price_per_mfa": 5.0,
    "pending_hours": 12,
    "hold_check_enabled": true
  }
}
```

Full keys (proxy formats, autobuy LTC wallet, reject filters, OTP bridge list) are in **`config/config.json.example`**.

---

## Configuration reference

| Key | Description |
|-----|-------------|
| `domain` | Domain for auto-created security emails (`alias@yourdomain.com`) |
| `mail.discord_webhook_all` | Discord webhook for every incoming email |
| `mail.discord_webhook_otp` | Discord webhook when an OTP is detected |
| `mail.otp_bridge_url` / `otp_bridge_urls` | Optional HTTP OTP bridge (e.g. playtime / treefarm) |
| `web.credentials` | Dashboard login + JWT secret |
| `proxy.proxies` | List of `host:port:user:pass` (or disable with `enabled: false`) |
| `coldproxy.*` | Optional Coldproxy residential package |
| `autosecure.reject.*` | Family / Game Pass / age / ban / phone / NFA-name filters |
| `autosecure.reject.gamepass` | Rejects **active** Game Pass only |
| `autobuy.pending_hours` | Default seller credit hold (hours) |
| `autobuy.client_plus_*` | Shorter hold for Client+ Discord role |
| `autobuy.security_email_check_interval_hours` | Pullback / security-email check during pending grace |
| `autobuy.hold_check_interval_hours` | First Microsoft lock check after sell |
| `autobuy.hold_check_second_interval_hours` | Second lock check delay after the first |
| `autobuy.ltc_wallet` | Litecoin payout wallet (`wif` / `address`) — keep private |

### `config/bot.json`

Command toggles, aliases, embed templates, button labels, presence, and post-verification behavior. No secrets. Prefer editing via the dashboard **Bot Config** tab when possible.

### API keys (optional)

| Service | URL | Used for |
|---------|-----|----------|
| Skytools | [developer.skytools.app](https://developer.skytools.app/) | Hypixel / SkyBlock stats |
| DonutSMP | [api.donutsmp.net](https://api.donutsmp.net/index.html) | Donut stats |
---

## Email & DNS

The bot runs an SMTP server on **port 25** when `autosecure-bot` starts. Mail is stored in SQLite and forwarded to Discord webhooks.

### Cloudflare DNS (DNS only / grey cloud)

| Type | Name | Value |
|------|------|-------|
| A | `mail` | Your VPS public IP |
| MX | `@` | `mail.yourdomain.com` (priority 10) |

Only one process should bind port 25 on the VPS (this bot — not a separate smtp-discord instance).

---

## Running with PM2

`ecosystem.config.cjs` starts three processes:

| Process | Port | Role |
|---------|------|------|
| `autosecure-bot` | 25 (SMTP) | Discord bot + mail server |
| `autosecure-api` | 8000 | FastAPI backend |
| `autosecure-web` | 3000 | Dashboard (Nitro build) |

```bash
pm2 start ecosystem.config.cjs
pm2 logs autosecure-bot
pm2 restart autosecure-bot autosecure-api autosecure-web
```

Update `CORS_ORIGINS` in `ecosystem.config.cjs` if you access the dashboard from a public IP or domain.

### Public access (optional)

Use Cloudflare Tunnel or nginx in front of ports 3000/8000. See upstream `cloudflared.yml` if you use a tunnel.

---

## Web dashboard

Default: `http://YOUR_VPS_IP:3000` (Nitro binds `0.0.0.0:3000`; API stays on `127.0.0.1:8000` and is proxied).

```bash
cp config/config.json.example config/config.json
# Set web.credentials.username / password / jwt_secret to values that are NOT the example placeholders
```

Login uses `web.credentials` in your local `config/config.json` (gitignored). **Enable 2FA** under Settings — the example password is a placeholder only and must be changed before going live.

| Tab | Description |
|-----|-------------|
| Overview | Stats and recent accounts |
| Accounts | Browse, search, view details, **delete** accounts |
| Secure | Manual / bulk securing |
| Emails | Security inboxes |
| Bot Config | Channels, commands, embeds |
| Settings | Dashboard password / 2FA |

---

## Bot commands

Command names can be renamed in `config/bot.json` or the dashboard.

| Command | Description |
|---------|-------------|
| `/secure` | Secure via recovery code or auth+password |
| `/check locked` | Check suspended / phone-locked status (admin) |
| `/email new` | Create `alias@domain` security email |
| `/email inbox` | View inbox for a security email |
| `/email list` | List stored security emails |
| `/request_otp` | Request OTP / 2FA bypass flow |
| `/auth code` | TOTP from 2FA secret |
| `/set channel` | Set logs / hits channels |
| `/send embed` | Send verification embed |
| `/stats hypixel` / `/stats donut` | Minecraft stats (needs API keys) |

---

## Troubleshooting

| Problem | What to check |
|---------|----------------|
| Bot won't start | Python 3.12+, venv deps, valid `bot_token`, intents enabled |
| Port 25 in use | Stop other SMTP (`pm2 stop mail` / smtp-discord); only one listener |
| Emails not arriving | DNS A/MX, port 25 open, `domain` in config matches MX domain |
| Wrong failure message on locked account | Re-pull this fork — lock detection runs before secure |
| Rejected for Game Pass but GP expired | Re-pull — filter matches product title + active cycle only |
| Secure stuck / false “No Minecraft” on CatB | Security email must receive OTP; bot completes Verify → remind LooksGood |
| Autobuy credits stuck pending | Check `hold_check_enabled` and intervals; Client+ role shortens hold |
| Dashboard login fails | `web.credentials` in `config/config.json` |
| `git push` goes to wrong host | `git remote set-url origin https://github.com/waitno01/autosecure.git` |
| Web build fails on Node 20 | Run `node node_modules/vite/bin/vite.js build` inside `web/` |

---

## Disclaimer

Use at your own risk. Automating Microsoft account flows may violate Microsoft's Terms of Service. This software is for educational purposes. The fork maintainers and upstream authors are not responsible for account actions taken by Microsoft or third parties.

**Do not commit** secrets or dumps. At minimum keep these out of git (see `.gitignore`):

- `config/config.json` — bot token, webhooks, proxies, LTC WIF
- `.env` / `.env.*`
- `database/*.db` — secured accounts
- `logs/`, `*.har`, cookie/cache dumps, `proxy_list.txt`, wallet keys
