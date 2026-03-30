#!/usr/bin/env node
// VulnScan Pro v3 — Telegram Bot (SQLite-backed)
const TelegramBot = require('node-telegram-bot-api');
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');
const path = require('path');

// === CONFIG ===
const TOKEN = process.env.BOT_TOKEN || '';
const BTC_ADDRESS = process.env.BTC_ADDRESS || '1BL4eV82zZ64Dp4cj3s9EgJ3ae8xPx5ZuJ';
const BASE = '/root/.openclaw/workspace/vulnscan-pro';
const ORDERS_FILE = `${BASE}/data/bot_orders.json`;
const OWNER_USERNAME = 'definitelynotmefr';
const FREE_SCANS_PER_USER = 3;

const PRICES = {
  free:  { sats: 0, label: 'FREE', targets: 1 },
  basic: { sats: 5000, label: 'BASIC $4', targets: 1 },
  pro:   { sats: 15000, label: 'PRO $12', targets: 5 },
  elite: { sats: 50000, label: 'ELITE $40', targets: 10 },
};

const bot = new TelegramBot(TOKEN, { polling: true });
console.log('[VulnScan Pro v3] Started');

// === DATABASE (SQLite) ===
const { db } = require('./db');

function logToDb(chatId, tier, target, txid, paidSats) {
  try {
    db.prepare(`INSERT INTO orders (chat_id, tier, actual_tier, target, txid, paid_sats, status, completed_at) VALUES (?, ?, ?, ?, ?, ?, 'complete', datetime('now'))`).run(chatId, tier, tier, target, txid || null, paidSats || 0);
  } catch (e) { console.error('[DB]', e.message); }
}

function ensureCredits(chatId) {
  try {
    db.prepare(`INSERT OR IGNORE INTO scan_credits (chat_id, credit_type, used, max_allowed) VALUES (?, 'free', 0, 3)`).run(chatId);
    db.prepare(`INSERT OR IGNORE INTO scan_credits (chat_id, credit_type, used, max_allowed) VALUES (?, 'pro_trial', 0, 2)`).run(chatId);
    db.prepare(`INSERT OR IGNORE INTO scan_credits (chat_id, credit_type, used, max_allowed) VALUES (?, 'elite_trial', 0, 2)`).run(chatId);
  } catch {}
}

function getUsedCountDb(chatId, type) {
  ensureCredits(chatId);
  try { return db.prepare(`SELECT used FROM scan_credits WHERE chat_id = ? AND credit_type = ?`).get(chatId, type)?.used || 0; } catch { return 0; }
}

function useCreditDb(chatId, type) {
  try { db.prepare(`UPDATE scan_credits SET used = used + 1 WHERE chat_id = ? AND credit_type = ? AND used < max_allowed`).run(chatId, type); } catch {}
}

function getOrderHistory(chatId) {
  try { return db.prepare(`SELECT * FROM orders WHERE chat_id = ? ORDER BY id DESC LIMIT 10`).all(chatId); } catch { return []; }
}

// === JSON STATE (runtime orders) ===
function loadOrders() { try { return JSON.parse(fs.readFileSync(ORDERS_FILE)); } catch { return []; } }
function saveOrders(orders) { fs.mkdirSync(path.dirname(ORDERS_FILE), { recursive: true }); fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2)); }
function getOrder(chatId) { return loadOrders().find(o => o.chatId === chatId && o.status !== 'complete'); }

// === HELPERS ===
function isOwner(msg) { return (msg.from?.username || '').toLowerCase() === OWNER_USERNAME; }
function canUseFree(chatId, msg) {
  if (isOwner(msg)) return true;
  return getUsedCountDb(chatId, 'free') < FREE_SCANS_PER_USER;
}
function canUseProTrial(chatId, msg) {
  if (isOwner(msg)) return true;
  return getUsedCountDb(chatId, 'pro_trial') < 2;
}
function canUseEliteTrial(chatId, msg) {
  if (isOwner(msg)) return true;
  return getUsedCountDb(chatId, 'elite_trial') < 2;
}
function freeLeft(chatId, msg) {
  if (isOwner(msg)) return '∞';
  return FREE_SCANS_PER_USER - getUsedCountDb(chatId, 'free');
}

function runTool(cmd, args, timeout = 60000) {
  return new Promise((resolve) => {
    let output = '';
    const proc = spawn(cmd, args);
    proc.stdout.on('data', d => output += d.toString());
    proc.stderr.on('data', d => output += d.toString());
    proc.on('close', () => resolve(output.trim()));
    proc.on('error', () => resolve(output.trim()));
    setTimeout(() => { try { proc.kill(); } catch {} resolve(output.trim()); }, timeout);
  });
}

function fetchUrl(urlStr, timeout = 8000) {
  return new Promise((resolve) => {
    try {
      const mod = urlStr.startsWith('https') ? https : http;
      const req = mod.get(urlStr, { timeout, headers: { 'User-Agent': 'Mozilla/5.0 VulnScanPro/3.0' } }, (res) => {
        const headers = res.headers || {};
        let data = '';
        res.on('data', c => { if (data.length < 50000) data += c; });
        res.on('end', () => resolve({ status: res.statusCode, headers, data }));
      });
      req.on('error', () => resolve({ status: 0, headers: {}, data: '' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, data: '' }); });
    } catch { resolve({ status: 0, headers: {}, data: '' }); }
  });
}

function checkTxReceived(txid) {
  return new Promise((resolve) => {
    https.get(`https://blockstream.info/api/tx/${txid}`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const tx = JSON.parse(data);
          let incoming = 0;
          for (const vout of tx.vout || []) { if (vout.scriptpubkey_address === BTC_ADDRESS) incoming += vout.value; }
          resolve({ sats: incoming });
        } catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

// === TECH DETECTION ===
function detectTech(headers, html) {
  const tech = [];
  const server = (headers['server'] || '').toLowerCase();
  const powered = (headers['x-powered-by'] || '').toLowerCase();
  const h = html.toLowerCase();
  if (server.includes('nginx')) tech.push('Nginx');
  if (server.includes('apache')) tech.push('Apache');
  if (server.includes('cloudflare')) tech.push('Cloudflare');
  if (server.includes('gunicorn')) tech.push('Gunicorn');
  if (powered.includes('express')) tech.push('Express.js');
  if (powered.includes('php')) tech.push('PHP');
  if (h.includes('wp-content') || h.includes('wordpress')) tech.push('WordPress');
  if (h.includes('react') || h.includes('__next')) tech.push('React');
  if (h.includes('vue.js') || h.includes('__vue')) tech.push('Vue.js');
  if (h.includes('angular')) tech.push('Angular');
  if (h.includes('jquery')) tech.push('jQuery');
  if (h.includes('tailwind')) tech.push('Tailwind CSS');
  if (h.includes('stripe')) tech.push('Stripe');
  if (h.includes('cloudflare')) tech.push('Cloudflare');
  if (h.includes('sentry')) tech.push('Sentry');
  return [...new Set(tech)];
}

// === SSL CHECK ===
async function getSSLInfo(domain) {
  // Sanitize: only allow alphanumeric, dots, hyphens
  const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, '');
  if (!safeDomain || safeDomain.length > 253) return null;
  try {
    const out = execSync(`echo | openssl s_client -connect ${safeDomain}:443 -servername ${safeDomain} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`, { timeout: 15000 }).toString();
    const info = {};
    for (const l of out.split('\n')) {
      if (l.startsWith('subject=')) info.subject = l.replace('subject=', '').trim();
      if (l.startsWith('issuer=')) info.issuer = l.replace('issuer=', '').trim();
      if (l.startsWith('notAfter=')) info.notAfter = l.replace('notAfter=', '').trim();
      if (l.includes('DNS:')) info.sans = (l.match(/DNS:[^\s,]+/g) || []).map(s => s.replace('DNS:', ''));
    }
    if (info.notAfter) {
      const days = Math.floor((new Date(info.notAfter) - Date.now()) / 86400000);
      info.daysLeft = days;
      info.expiryWarning = days < 30 ? `⚠️ Expires in ${days} days!` : null;
    }
    return info;
  } catch { return null; }
}

// === SCREENSHOT ===
async function takeScreenshot(url, outPath) {
  try {
    execSync(`chromium --headless --no-sandbox --disable-gpu --screenshot="${outPath}" --window-size=1280,900 --hide-scrollbars "${url}" 2>/dev/null`, { timeout: 20000 });
    return fs.existsSync(outPath) && fs.statSync(outPath).size > 1000;
  } catch { return false; }
}

// === EXPOSURE SCORE ===
function calcScore(r) {
  let s = 100;
  s -= r.sensitive.length * 15;
  s -= r.corsVuln.length * 12;
  s -= r.corsWild.length * 5;
  s -= Math.min(r.headers.length * 3, 20);
  s -= r.nuclei.filter(n => n.includes('[critical]')).length * 20;
  s -= r.nuclei.filter(n => n.includes('[high]')).length * 10;
  if (r.ssl?.expiryWarning) s -= 10;
  return Math.max(0, Math.min(100, s));
}
function scoreEmoji(s) { return s >= 90 ? '🟢' : s >= 70 ? '🟡' : s >= 50 ? '🟠' : '🔴'; }

// === SCANNER ===
async function scanTarget(target, tier) {
  const outDir = `${BASE}/reports/${new Date().toISOString().replace(/[:.]/g,'-').slice(0,19)}_${target.replace(/[^a-zA-Z0-9.-]/g,'')}`;
  fs.mkdirSync(outDir, { recursive: true });
  const r = { subdomains: [], liveHosts: [], tech: [], sensitive: [], corsVuln: [], corsWild: [], headers: [], nuclei: [], ssl: null, robots: [], sitemap: [] };
  const isPaid = tier !== 'free';
  const isPro = tier === 'pro' || tier === 'elite';

  // 1. Subdomains
  const subOut = await runTool('subfinder', ['-d', target, '-silent', '-timeout', '30', '-max-time', '60'], 90000);
  const found = subOut.split('\n').filter(s => s.trim() && s.includes('.'));
  const base = target.toLowerCase().replace(/^www\./, '');
  r.subdomains = [...new Set([...found, base, `www.${base}`, `api.${base}`, `mail.${base}`, `staging.${base}`, `dev.${base}`])].slice(0, tier === 'free' ? 20 : 150);
  fs.writeFileSync(`${outDir}/subdomains.txt`, r.subdomains.join('\n'));

  // 2. Live hosts
  const maxLive = tier === 'free' ? 5 : tier === 'basic' ? 10 : 25;
  const httpxInput = r.subdomains.slice(0, maxLive).map(d => d.startsWith('http') ? d : `https://${d}`).join('\n');
  fs.writeFileSync(`${outDir}/httpx_input.txt`, httpxInput);
  const httpxOut = await runTool('httpx', ['-silent', '-timeout', '5', '-threads', '20', '-title', '-tech-detect', '-status-code', '-l', `${outDir}/httpx_input.txt`], 60000);
  r.liveHosts = httpxOut.split('\n').filter(s => s.trim()).map(s => s.split(' ')[0]).filter(u => u.startsWith('http'));
  if (r.liveHosts.length === 0) {
    for (const d of r.subdomains.slice(0, 5)) {
      const url = d.startsWith('http') ? d : `https://${d}`;
      const check = await fetchUrl(url);
      if (check.status > 0) r.liveHosts.push(url);
    }
  }
  fs.writeFileSync(`${outDir}/live_hosts.txt`, r.liveHosts.join('\n'));

  if (!isPaid) {
    fs.writeFileSync(`${outDir}/REPORT.md`, genReport(target, tier, r));
    return { outDir, results: r };
  }

  // 3. Tech + robots + sitemap + SSL
  const maxCheck = tier === 'basic' ? 3 : 8;
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    const resp = await fetchUrl(url);
    if (resp.status > 0) r.tech.push(...detectTech(resp.headers, resp.data));
    if (url === r.liveHosts[0]) {
      const robots = await fetchUrl(`${url}/robots.txt`);
      if (robots.status === 200 && robots.data.length > 10) {
        r.robots = robots.data.split('\n').filter(l => l.toLowerCase().startsWith('disallow:')).map(l => l.split(':').slice(1).join(':').trim()).filter(p => p).slice(0, 20);
      }
      const sitemap = await fetchUrl(`${url}/sitemap.xml`);
      if (sitemap.status === 200 && sitemap.data.includes('<loc>')) {
        r.sitemap = (sitemap.data.match(/<loc>([^<]+)<\/loc>/g) || []).map(l => l.replace(/<\/?loc>/g, '')).slice(0, 20);
      }
    }
  }
  r.tech = [...new Set(r.tech)];
  r.ssl = await getSSLInfo(base);

  // 4. Sensitive files
  const paths = ['.git/config', '.env', '.env.bak', '.DS_Store', 'server-status', 'actuator', 'actuator/health', 'wp-login.php', 'admin', 'phpinfo.php', '.htaccess', 'elmah.axd', 'debug/pprof'];
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    for (const p of paths) {
      const resp = await fetchUrl(`${url}/${p}`);
      if (resp.status === 200 && resp.data.length > 20) {
        const cl = resp.data.toLowerCase();
        if (!cl.includes('blocked') && !cl.includes('rejected') && !cl.includes('unauthorized')) r.sensitive.push(`[200] ${url}/${p}`);
      }
    }
  }

  // 5. CORS
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    // Validate URL to prevent command injection
    if (!url.match(/^https?:\/\/[a-zA-Z0-9.\-]+/)) continue;
    try {
      const ch = execSync(`curl -sI --max-time 5 -H "Origin: https://evil.com" "${url}" 2>/dev/null | grep -i "access-control-allow-origin"`, { timeout: 10000 }).toString().trim();
      if (ch.includes('evil.com')) r.corsVuln.push(url);
      else if (ch.includes('*')) r.corsWild.push(url);
    } catch {}
  }

  // 6. Headers
  const required = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options'];
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    const resp = await fetchUrl(url);
    if (resp.status > 0) {
      const missing = required.filter(h => !JSON.stringify(resp.headers).toLowerCase().includes(h));
      if (missing.length > 0) r.headers.push({ url, missing });
    }
  }

  // 7. Nuclei (pro/elite)
  if (isPro && r.liveHosts.length > 0) {
    fs.writeFileSync(`${outDir}/nuclei_targets.txt`, r.liveHosts.join('\n'));
    const nucleiOut = await runTool('nuclei', ['-l', `${outDir}/nuclei_targets.txt`, '-severity', 'critical,high,medium', '-type', 'http', '-timeout', '8', '-retries', '1', '-c', '15', '-rl', '30', '-silent'], 120000);
    r.nuclei = nucleiOut.split('\n').filter(s => s.trim());
  }

  // 8. Screenshots (pro/elite)
  if (isPro) for (const url of r.liveHosts.slice(0, 3)) await takeScreenshot(url, `${outDir}/screenshot_${url.replace(/[^a-zA-Z0-9]/g,'_')}.png`);

  fs.writeFileSync(`${outDir}/REPORT.md`, genReport(target, tier, r));
  if (tier === 'elite') fs.writeFileSync(`${outDir}/BOUNTY_REPORT.md`, genBountyReport(target, r));
  return { outDir, results: r };
}

// === REPORT ===
function genReport(target, tier, r) {
  const score = tier !== 'free' ? calcScore(r) : null;
  let report = `# VulnScan Pro — Security Report\n\n**Target:** ${target}\n**Tier:** ${PRICES[tier].label}\n**Date:** ${new Date().toUTCString()}\n\n---\n`;
  if (score !== null) report += `## ${scoreEmoji(score)} Exposure Score: ${score}/100\n\n---\n`;
  report += `## Summary\n\n| Finding | Count |\n|---------|-------|\n| Subdomains | ${r.subdomains.length} |\n| Live hosts | ${r.liveHosts.length} |\n`;
  if (tier !== 'free') report += `| Technologies | ${r.tech.length} |\n| Sensitive files | ${r.sensitive.length} |\n| CORS vuln | ${r.corsVuln.length} |\n| Missing headers | ${r.headers.length} |\n`;
  if (r.nuclei.length) report += `| Nuclei findings | ${r.nuclei.length} |\n`;
  report += `\n## Live Hosts\n${r.liveHosts.length > 0 ? r.liveHosts.map(h => `- ${h}`).join('\n') : 'None found'}\n`;
  if (tier !== 'free') {
    if (r.tech.length) report += `\n## Technologies\n${r.tech.map(t => `- ${t}`).join('\n')}\n`;
    if (r.sensitive.length) report += `\n## ⚠️ Sensitive Files\n${r.sensitive.map(s => `- ${s}`).join('\n')}\n`;
    if (r.corsVuln.length) report += `\n## 🔴 CORS Vulnerable\n${r.corsVuln.map(c => `- ${c}`).join('\n')}\n`;
    if (r.corsWild.length) report += `\n## 🟡 CORS Wildcard\n${r.corsWild.map(c => `- ${c}`).join('\n')}\n`;
    if (r.headers.length) report += `\n## Missing Headers\n${r.headers.map(h => `- ${h.url} → ${h.missing.join(', ')}`).join('\n')}\n`;
    if (r.ssl) report += `\n## SSL\n- Expires: ${r.ssl.notAfter || 'N/A'}${r.ssl.expiryWarning ? ` ${r.ssl.expiryWarning}` : ''}\n- SANs: ${(r.ssl.sans||[]).slice(0,8).join(', ')}\n`;
    if (r.robots.length) report += `\n## robots.txt\n${r.robots.map(p => `- ${p}`).join('\n')}\n`;
  }
  if (r.nuclei.length) report += `\n## 🔴 Nuclei\n${r.nuclei.map(n => `- ${n}`).join('\n')}\n`;
  if (tier === 'elite') {
    report += `\n## Prioritized Fixes\n`;
    const f = [];
    if (r.sensitive.length) f.push('1. **URGENT:** Remove exposed sensitive files');
    if (r.corsVuln.length) f.push('2. **HIGH:** Fix CORS misconfiguration');
    if (r.nuclei.filter(n=>n.includes('[critical]')).length) f.push('3. **CRITICAL:** Patch critical CVEs');
    if (r.headers.length) f.push('4. Add missing security headers');
    if (r.ssl?.expiryWarning) f.push('5. Renew SSL certificate');
    report += f.length ? f.join('\n') : 'No critical issues.\n';
  }
  report += `\n---\n*VulnScan Pro*`;
  return report;
}

function genBountyReport(target, r) {
  let report = `# Vulnerability Report — ${target}\n\n**Date:** ${new Date().toUTCString()}\n\n`;
  let idx = 1;
  if (r.sensitive.length) report += `## ${idx++}. Exposed Sensitive Files\n**Severity:** High\n${r.sensitive.map(s=>`- ${s.replace('[200] ','')}`).join('\n')}\n\n---\n\n`;
  if (r.corsVuln.length) report += `## ${idx++}. CORS Misconfiguration\n**Severity:** Medium\n${r.corsVuln.map(c=>`- ${c}`).join('\n')}\n\n---\n\n`;
  for (const n of r.nuclei) if (n.includes('[critical]') || n.includes('[high]')) report += `## ${idx++}. ${n}\n**Severity:** ${n.includes('[critical]')?'Critical':'High'}\n\n---\n\n`;
  if (idx === 1) report += 'No critical vulnerabilities found.\n';
  return report;
}

// === COMMANDS ===
bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  const owner = isOwner(msg);
  ensureCredits(chatId);
  const fl = freeLeft(chatId, msg);
  const pt = canUseProTrial(chatId, msg);
  const et = canUseEliteTrial(chatId, msg);
  bot.sendMessage(chatId, `🔍 VulnScan Pro — Automated Security Recon

${owner ? '🔓 Unlimited access' : `🆓 ${fl} free scans${pt ? ' + 2× Pro trial' : ''}${et ? ' + 2× Elite trial' : ''}`}

Quick start:
/order → pick tier → send domain → get report

Commands:
/order — start a scan
/status — current order
/myorders — order history
/share — copy promo
/help — all commands

$4 Basic · $12 Pro · $40 Elite`);
});

bot.onText(/\/order/, (msg) => {
  const chatId = msg.chat.id;
  if (getOrder(chatId)) return bot.sendMessage(chatId, 'Active order. Send target or /cancel');
  ensureCredits(chatId);
  const owner = isOwner(msg);
  const fl = canUseFree(chatId, msg);
  const pt = canUseProTrial(chatId, msg);
  const et = canUseEliteTrial(chatId, msg);
  const freeCount = freeLeft(chatId, msg);
  const orders = loadOrders();
  orders.push({ chatId, status: 'awaiting_tier', created: new Date().toISOString() });
  saveOrders(orders);
  let menu = 'Choose:\n\n';
  if (owner) menu += '🔓 All free for you!\nfree | basic | pro | elite\n';
  else {
    if (fl) menu += `🆓 free — ${freeCount} left (subdomains + hosts)\n`;
    if (pt) menu += '🥈 pro-trial — 2 free Pro scans!\n';
    if (et) menu += '🥇 elite-trial — 2 free Elite scans!\n';
    menu += '🥉 basic $4 | 🥈 pro $12 | 🥇 elite $40\n';
  }
  const valid = ['free'];
  if (pt && !owner) valid.push('pro-trial');
  if (et && !owner) valid.push('elite-trial');
  valid.push('basic', 'pro', 'elite');
  menu += `\nReply: ${valid.join(', ')}`;
  bot.sendMessage(chatId, menu);
});

bot.onText(/\/status|\/check/, (msg) => {
  const orders = loadOrders().filter(o => o.chatId === msg.chat.id);
  if (!orders.length) return bot.sendMessage(msg.chat.id, 'No orders. /order to start');
  const last = orders[orders.length - 1];
  bot.sendMessage(msg.chat.id, `Last: ${last.target || 'pending'} | ${(last.actual_tier||last.tier||'?').toUpperCase()} | ${last.status}`);
});

bot.onText(/\/myorders/, (msg) => {
  const chatId = msg.chat.id;
  const orders = getOrderHistory(chatId);
  if (!orders.length) return bot.sendMessage(chatId, 'No history yet. /order to start!');
  let text = '📋 Order History:\n\n';
  for (const o of orders) {
    const date = (o.completed_at || o.created_at || '').slice(0, 10);
    text += `• ${o.target || 'N/A'} | ${(o.actual_tier||o.tier).toUpperCase()} | ${o.paid_sats > 0 ? o.paid_sats+'sats' : 'free'} | ${date}\n`;
  }
  bot.sendMessage(chatId, text);
});

bot.onText(/\/cancel/, (msg) => {
  const chatId = msg.chat.id;
  saveOrders(loadOrders().filter(o => o.chatId !== chatId || o.status === 'complete'));
  bot.sendMessage(chatId, '✅ Cancelled.');
});

bot.onText(/\/share/, (msg) => {
  bot.sendMessage(msg.chat.id, `Copy & share:\n\n🔍 Free security scan — subdomains, live hosts, tech stack, SSL, CVEs, screenshots, Exposure Score (0-100).\n\nTry: @vulnscan_pro_bot\n\n#bugbounty #infosec`);
});

bot.onText(/\/balance/, (msg) => {
  fetchUrl(`https://blockstream.info/api/address/${BTC_ADDRESS}`).then(r => {
    try { const d = JSON.parse(r.data); const bal = d.chain_stats.funded_txo_sum - d.chain_stats.spent_txo_sum; bot.sendMessage(msg.chat.id, `💰 ${bal} sats (${(bal/1e8).toFixed(8)} BTC)`); }
    catch { bot.sendMessage(msg.chat.id, 'Could not check'); }
  });
});

bot.onText(/\/help/, (msg) => {
  bot.sendMessage(msg.chat.id, `Commands:\n/start — welcome\n/order — new scan\n/status — current order\n/myorders — history\n/cancel — cancel\n/share — promo\n/balance — BTC\n/help — this\n\nFree: subdomains + hosts\nPaid: + tech, SSL, CORS, headers, nuclei, screenshots, score`);
});

// === MESSAGE HANDLER ===
bot.on('message', async (msg) => {
  if (msg.text?.startsWith('/')) return;
  const chatId = msg.chat.id;
  const text = (msg.text || '').trim();
  if (!text) return;

  const orders = loadOrders();
  const active = orders.find(o => o.chatId === chatId && o.status !== 'complete');
  if (!active) return bot.sendMessage(chatId, 'Hi! /order to start.');

  if (active.status === 'awaiting_tier') {
    const tier = text.toLowerCase().replace(/\s+/g, '-');
    const owner = isOwner(msg);
    const fl = canUseFree(chatId, msg);
    const pt = canUseProTrial(chatId, msg);
    const et = canUseEliteTrial(chatId, msg);
    const valid = ['free', 'basic', 'pro', 'elite'];
    if (pt && !owner) valid.splice(1, 0, 'pro-trial');
    if (et && !owner) valid.splice(pt ? 2 : 1, 0, 'elite-trial');
    if (!valid.includes(tier)) return bot.sendMessage(chatId, `Valid: ${valid.join(', ')}`);

    const isProTrial = tier === 'pro-trial';
    const isEliteTrial = tier === 'elite-trial';
    active.tier = tier;
    active.actualTier = isProTrial ? 'pro' : isEliteTrial ? 'elite' : tier;

    if (owner || tier === 'free' || isProTrial || isEliteTrial) {
      active.status = 'awaiting_target';
      active.paid_sats = 0;
      saveOrders(orders);
      const label = owner ? `${tier.toUpperCase()} (owner)` : isProTrial ? 'PRO TRIAL' : isEliteTrial ? 'ELITE TRIAL' : 'Free scan';
      bot.sendMessage(chatId, `${owner ? '🔓' : '🆓'} ${label}!\nSend target: example.com`);
    } else {
      active.status = 'awaiting_payment';
      saveOrders(orders);
      bot.sendMessage(chatId, `${PRICES[tier].label}\nSend ${(PRICES[tier].sats/1e8).toFixed(8)} BTC to:\n${BTC_ADDRESS}\n\nThen send TX ID.`);
    }
    return;
  }

  if (active.status === 'awaiting_payment') {
    const txMatch = text.match(/[a-fA-F0-9]{64}/);
    if (!txMatch) return bot.sendMessage(chatId, 'Send your TX ID (64 hex chars).');
    bot.sendMessage(chatId, '🔍 Verifying...');
    const txInfo = await checkTxReceived(txMatch[0]);
    if (txInfo && txInfo.sats >= PRICES[active.tier].sats) {
      active.txid = txMatch[0]; active.paid_sats = txInfo.sats; active.status = 'awaiting_target'; saveOrders(orders);
      bot.sendMessage(chatId, `✅ ${txInfo.sats} sats confirmed!\nSend your target domain.`);
    } else {
      bot.sendMessage(chatId, txInfo ? `⚠️ ${txInfo.sats} sats (need ${PRICES[active.tier].sats})` : '❌ TX not found.');
    }
    return;
  }

  if (active.status === 'awaiting_target') {
    let target = text.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/[^a-zA-Z0-9.\-]/g, '').trim();
    if (!target.match(/^[a-zA-Z0-9]/)) return bot.sendMessage(chatId, `"${target}" isn't a domain.`);
    active.target = target; active.status = 'scanning'; saveOrders(orders);
    const scanTier = active.actualTier || active.tier;
    bot.sendMessage(chatId, `🔍 Scanning ${target} (${PRICES[scanTier].label})...\n${scanTier === 'free' ? 'Quick scan' : 'Full scan — 2-5 min'}`);

    try {
      const { outDir, results } = await scanTarget(target, scanTier);
      const score = scanTier !== 'free' ? calcScore(results) : null;

      // Track credits
      if (!isOwner(msg)) {
        if (active.tier === 'free') useCreditDb(chatId, 'free');
        if (active.tier === 'pro-trial') useCreditDb(chatId, 'pro_trial');
        if (active.tier === 'elite-trial') useCreditDb(chatId, 'elite_trial');
      }

      let summary = `✅ ${target} — Done\n\n${results.subdomains.length} subdomains · ${results.liveHosts.length} live hosts\n`;
      if (score !== null) summary += `${scoreEmoji(score)} Score: ${score}/100\n`;
      if (results.tech.length) summary += `🔧 ${results.tech.slice(0,6).join(', ')}\n`;
      if (results.sensitive.length) summary += `⚠️ ${results.sensitive.length} sensitive files\n`;
      if (results.corsVuln.length) summary += `🔴 ${results.corsVuln.length} CORS vulns\n`;
      if (results.nuclei.length) summary += `🦠 ${results.nuclei.length} nuclei findings\n`;

      await bot.sendMessage(chatId, summary);
      const reportPath = `${outDir}/REPORT.md`;
      if (fs.existsSync(reportPath)) await bot.sendDocument(chatId, reportPath, { caption: `📄 ${target}` });

      if (scanTier === 'pro' || scanTier === 'elite') {
        const shots = fs.readdirSync(outDir).filter(f => f.startsWith('screenshot_'));
        for (const s of shots.slice(0, 2)) await bot.sendPhoto(chatId, `${outDir}/${s}`);
      }
      if (scanTier === 'elite') {
        const bp = `${outDir}/BOUNTY_REPORT.md`;
        if (fs.existsSync(bp)) await bot.sendDocument(chatId, bp, { caption: '📝 Bounty report' });
      }

      // Log to DB
      logToDb(chatId, active.tier, target, active.txid, active.paid_sats);

      active.status = 'complete'; active.reportPath = reportPath; active.completed = new Date().toISOString(); saveOrders(orders);
    } catch (err) {
      console.error('[SCAN]', err.message);
      bot.sendMessage(chatId, `❌ Error: ${err.message}`);
      active.status = 'complete'; saveOrders(orders);
    }
    return;
  }

  bot.sendMessage(chatId, `Status: ${active.status}. /status for info.`);
});

bot.on('polling_error', (err) => console.error('[Poll]', err.message));
console.log('[VulnScan Pro v3] Ready!');
