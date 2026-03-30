#!/usr/bin/env node
// VulnScan Pro — Web Server
const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { spawn, execSync } = require('child_process');
const { db } = require('./bot/db');

const app = express();
const PORT = 3000;
const BASE = '/root/.openclaw/workspace/vulnscan-pro';
const BTC_ADDRESS = process.env.BTC_ADDRESS || '1BL4eV82zZ64Dp4cj3s9EgJ3ae8xPx5ZuJ';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'web')));

const PRICES = {
  free:  { sats: 0, label: 'FREE', targets: 1 },
  basic: { sats: 5000, label: 'BASIC $4', targets: 1 },
  pro:   { sats: 15000, label: 'PRO $12', targets: 5 },
  elite: { sats: 50000, label: 'ELITE $40', targets: 10 },
};

// === Scans in progress ===
const activeScans = new Map();

// === Scanner (reused from bot) ===
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
      const req = https.get(urlStr, { timeout, headers: { 'User-Agent': 'Mozilla/5.0 VulnScanPro/3.0' } }, (res) => {
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
  if (h.includes('sentry')) tech.push('Sentry');
  return [...new Set(tech)];
}

async function getSSLInfo(domain) {
  try {
    const out = execSync(`echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`, { timeout: 15000 }).toString();
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
      info.expiryWarning = days < 30 ? `Expires in ${days} days!` : null;
    }
    return info;
  } catch { return null; }
}

async function takeScreenshot(url, outPath) {
  try {
    execSync(`chromium --headless --no-sandbox --disable-gpu --screenshot="${outPath}" --window-size=1280,900 --hide-scrollbars "${url}" 2>/dev/null`, { timeout: 20000 });
    return fs.existsSync(outPath) && fs.statSync(outPath).size > 1000;
  } catch { return false; }
}

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

async function scanTarget(target, tier, scanId) {
  const outDir = `${BASE}/reports/web_${scanId}_${target.replace(/[^a-zA-Z0-9.-]/g,'')}`;
  fs.mkdirSync(outDir, { recursive: true });
  const r = { subdomains: [], liveHosts: [], tech: [], sensitive: [], corsVuln: [], corsWild: [], headers: [], nuclei: [], ssl: null, robots: [], sitemap: [] };
  const isPaid = tier !== 'free';
  const isPro = tier === 'pro' || tier === 'elite';

  const update = (pct, msg) => {
    activeScans.set(scanId, { pct, msg, done: false });
  };

  update(5, 'Enumerating subdomains...');
  const subOut = await runTool('subfinder', ['-d', target, '-silent', '-timeout', '30', '-max-time', '60'], 90000);
  const found = subOut.split('\n').filter(s => s.trim() && s.includes('.'));
  const base = target.toLowerCase().replace(/^www\./, '');
  r.subdomains = [...new Set([...found, base, `www.${base}`, `api.${base}`, `mail.${base}`, `staging.${base}`, `dev.${base}`])].slice(0, tier === 'free' ? 20 : 150);

  update(20, 'Detecting live hosts...');
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

  if (!isPaid) {
    update(100, 'Done!');
    return r;
  }

  update(35, 'Detecting technologies...');
  const maxCheck = tier === 'basic' ? 3 : 8;
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    const resp = await fetchUrl(url);
    if (resp.status > 0) r.tech.push(...detectTech(resp.headers, resp.data));
    if (url === r.liveHosts[0]) {
      const robots = await fetchUrl(`${url}/robots.txt`);
      if (robots.status === 200 && robots.data.length > 10) r.robots = robots.data.split('\n').filter(l => l.toLowerCase().startsWith('disallow:')).map(l => l.split(':').slice(1).join(':').trim()).filter(p => p).slice(0, 20);
      const sitemap = await fetchUrl(`${url}/sitemap.xml`);
      if (sitemap.status === 200 && sitemap.data.includes('<loc>')) r.sitemap = (sitemap.data.match(/<loc>([^<]+)<\/loc>/g) || []).map(l => l.replace(/<\/?loc>/g, '')).slice(0, 20);
    }
  }
  r.tech = [...new Set(r.tech)];
  r.ssl = await getSSLInfo(base);

  update(50, 'Checking sensitive files...');
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

  update(65, 'Checking CORS & headers...');
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    try {
      const ch = execSync(`curl -sI --max-time 5 -H "Origin: https://evil.com" "${url}" 2>/dev/null | grep -i "access-control-allow-origin"`, { timeout: 10000 }).toString().trim();
      if (ch.includes('evil.com')) r.corsVuln.push(url);
      else if (ch.includes('*')) r.corsWild.push(url);
    } catch {}
  }
  const required = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options'];
  for (const url of r.liveHosts.slice(0, maxCheck)) {
    const resp = await fetchUrl(url);
    if (resp.status > 0) {
      const missing = required.filter(h => !JSON.stringify(resp.headers).toLowerCase().includes(h));
      if (missing.length > 0) r.headers.push({ url, missing });
    }
  }

  if (isPro) {
    update(80, 'Running nuclei CVE scan...');
    if (r.liveHosts.length > 0) {
      fs.writeFileSync(`${outDir}/nuclei_targets.txt`, r.liveHosts.join('\n'));
      const nucleiOut = await runTool('nuclei', ['-l', `${outDir}/nuclei_targets.txt`, '-severity', 'critical,high,medium', '-type', 'http', '-timeout', '8', '-retries', '1', '-c', '15', '-rl', '30', '-silent'], 120000);
      r.nuclei = nucleiOut.split('\n').filter(s => s.trim());
    }

    update(90, 'Taking screenshots...');
    for (const url of r.liveHosts.slice(0, 3)) {
      const shotPath = `${outDir}/screenshot_${url.replace(/[^a-zA-Z0-9]/g,'_')}.png`;
      await takeScreenshot(url, shotPath);
    }
  }

  update(100, 'Done!');
  return r;
}

// === API Routes ===
app.post('/api/scan', async (req, res) => {
  const { target, tier, freeId } = req.body;
  if (!target || !tier) return res.status(400).json({ error: 'Missing target or tier' });

  const cleanTarget = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  if (!cleanTarget.match(/^[a-zA-Z0-9]/)) return res.status(400).json({ error: 'Invalid domain' });

  const scanId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  activeScans.set(scanId, { pct: 0, msg: 'Starting...', done: false });

  // Run scan async
  scanTarget(cleanTarget, tier, scanId).then(results => {
    activeScans.set(scanId, { pct: 100, msg: 'Done!', done: true, results });
    // Log to DB
    try {
      db.prepare(`INSERT INTO orders (chat_id, tier, actual_tier, target, status, paid_sats, completed_at) VALUES (?, ?, ?, ?, 'complete', 0, datetime('now'))`).run(freeId || 0, tier, tier, cleanTarget);
    } catch {}
  }).catch(err => {
    activeScans.set(scanId, { pct: 100, msg: 'Error: ' + err.message, done: true, error: err.message });
  });

  res.json({ scanId, message: 'Scan started' });
});

app.get('/api/scan/:id', (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

app.get('/api/balance', async (req, res) => {
  try {
    const data = await new Promise((resolve, reject) => {
      https.get(`https://blockstream.info/api/address/${BTC_ADDRESS}`, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => resolve(JSON.parse(d)));
      }).on('error', reject);
    });
    const bal = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
    res.json({ sats: bal, btc: (bal / 1e8).toFixed(8) });
  } catch { res.json({ sats: 0, btc: '0' }); }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[VulnScan Web] Running on http://0.0.0.0:${PORT}`);
});
