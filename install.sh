#!/bin/bash
# VulnScan Pro — One-line install
# Usage: bash install.sh

set -e

echo "🔍 Installing VulnScan Pro..."

# Check dependencies
command -v node >/dev/null 2>&1 || { echo "❌ Node.js required. Install from nodejs.org"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "❌ Go required. Install from go.dev"; exit 1; }

# Install recon tools
echo "📦 Installing recon tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
go install -v github.com/projectdiscovery/httpx/v2/cmd/httpx@latest 2>/dev/null
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null

# Download nuclei templates
echo "📋 Downloading nuclei templates..."
nuclei -update-templates 2>/dev/null || true

# Install Node dependencies
echo "📦 Installing Node dependencies..."
npm install
cd bot && npm install && cd ..

echo ""
echo "✅ VulnScan Pro installed!"
echo ""
echo "To run:"
echo "  export BOT_TOKEN=your_telegram_bot_token"
echo "  export BTC_ADDRESS=your_btc_address"
echo "  node bot/index.js     # Telegram bot"
echo "  node web-server.js    # Web interface"
echo ""
echo "Or use Docker:"
echo "  docker-compose up -d"
