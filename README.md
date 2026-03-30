# 🔍 VulnScan Pro — Automated Security Reconnaissance

A Telegram bot that performs comprehensive security reconnaissance on any target domain. Built for bug bounty hunters, penetration testers, and security researchers.

## Features

- **Subdomain Enumeration** — Discovers subdomains using subfinder
- **Live Host Detection** — Finds active hosts with httpx
- **Technology Fingerprinting** — Identifies CMS, frameworks, servers (WordPress, React, Cloudflare, etc.)
- **SSL Certificate Analysis** — Expiry, issuer, SANs
- **robots.txt / Sitemap Discovery** — Finds hidden paths
- **Sensitive File Exposure** — Checks for .git, .env, actuator, admin panels
- **CORS Misconfiguration Detection** — Finds reflected origin vulnerabilities
- **Security Header Audit** — CSP, HSTS, X-Frame-Options, etc.
- **Nuclei CVE Scan** — Known vulnerability detection
- **Screenshots** — Headless Chromium capture of live hosts
- **Exposure Score (0-100)** — Single metric summarizing security posture
- **Bounty-Ready Reports** — Formatted for direct HackerOne submission

## Quick Start

### Telegram Bot
Try it now: [@vulnscan_pro_bot](https://t.me/vulnscan_pro_bot)

### Self-Hosted
```bash
# Clone the repo
git clone https://github.com/Loran4vr/vulnscan-pro.git
cd vulnscan-pro

# Install dependencies
npm install

# Install recon tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Run the bot
BOT_TOKEN=your_telegram_bot_token node bot/index.js

# Run the web server
node web-server.js
```

## Pricing (Hosted Service)

| Tier | Price | Features |
|------|-------|----------|
| 🆓 Free | $0 | 3 scans, subdomains + live hosts |
| 🥉 Basic | $4 | Full scan, 1 target |
| 🥈 Pro | $12 | + Nuclei CVEs + Exposure Score, 5 targets |
| 🥇 Elite | $40 | + Bounty-ready report, 10 targets |

## Architecture

```
vulnscan-pro/
├── bot/
│   ├── index.js      # Telegram bot (v3)
│   └── db.js         # SQLite database
├── web/
│   └── index.html    # Web interface
├── web-server.js     # Express web server
├── src/
│   ├── scanner.sh    # Bash scanner (legacy)
│   ├── payment_monitor.py  # BTC payment verification
│   └── order_handler.py    # Order management
└── data/
    ├── vulnscan.db   # SQLite database
    └── bot_orders.json  # Runtime state
```

## Tools Used

- [subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain discovery
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing
- [nuclei](https://github.com/projectdiscovery/nuclei) — Vulnerability scanning
- [Node.js](https://nodejs.org) — Bot & web server
- [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) — Database
- [node-telegram-bot-api](https://github.com/yagop/node-telegram-bot-api) — Telegram integration

## Support

- Telegram: [@vulnscan_pro_bot](https://t.me/vulnscan_pro_bot)
- BTC: `1BL4eV82zZ64Dp4cj3s9EgJ3ae8xPx5ZuJ`

## License

MIT
