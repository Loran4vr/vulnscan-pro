#!/bin/bash
cd /root/.openclaw/workspace/vulnscan-pro
exec node bot/index.js >> data/bot.log 2>&1
