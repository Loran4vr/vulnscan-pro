#!/usr/bin/env node
// VulnScan Pro — Auto Tweeter v2
// High-quality content that provides value first, promo second
// Posts once per day, rotates through content types
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');

const CK = 'asXLiYQEGCUM5rfdWNms7hcMb';
const CS = '0jZfxOeDElxIxXQ8yAZhTXqX7D8ZZdPon90sWShu9wQuxR3gnw';
const AT = '2038610379366903809-pjv6HX1NoIwYmKljfmK9QQJFZxuko6';
const ATS = 'hEkxt8migXDFSdzAd80Ffx9DtDr2OzbNaEGEIml7wxPy1';

const STATE_FILE = path.join(__dirname, 'data', 'tweet_state.json');

// High-quality tweets — value first, promo subtle
const TWEETS = [
  // Security tips (no promo, pure value)
  `Quick bug bounty tip:

Before you start digging into a target, check these 3 things first:

1. robots.txt — often reveals hidden admin panels and API endpoints
2. sitemap.xml — shows the full site structure they don't want indexed
3. /.git/config — if exposed, you can dump their entire source code

30 seconds of recon saves hours of guessing.`,

  // Interesting finding (anonymized)
  `Found a CORS misconfiguration on a major fintech site today:

Server reflected ANY origin header back as Access-Control-Allow-Origin.

That means any website can make authenticated requests to their API on behalf of logged-in users.

Always check: curl -sI -H "Origin: https://evil.com" https://target.com

If you see "evil.com" reflected, that's a bug.`,

  // Tool tip
  `Stop manually checking for exposed .git directories.

One command to check 15 sensitive paths on any target:

for path in .git/config .env .env.bak .DS_Store server-status actuator wp-login.php admin phpinfo.php .htaccess elmah.axd debug/pprof; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target/$path")
  echo "[$code] $path"
done

Found exposed actuator endpoints worth $500+ bounties with this.`,

  // Security headers check
  `Most websites are missing basic security headers.

Quick check:
curl -sI https://target.com | grep -i "x-frame-options\|content-security-policy\|strict-transport-security\|x-content-type-options"

Missing CSP + X-Frame-Options = clickjacking vulnerability worth reporting.

Missing HSTS = SSL stripping attack possible.

Low-hanging fruit, but it's valid and often pays.`,

  // Recon workflow
  `My bug bounty recon workflow (automated):

1. subfinder -d target.com → all subdomains
2. httpx -silent → which ones are alive
3. Check for sensitive files (.git, .env, actuator)
4. CORS + security header check
5. nuclei -severity critical,high → known CVEs

Takes 2 minutes, catches 80% of easy wins before you start manual testing.`,

  // SSL certificate tip
  `Bug bounty tip: SSL certificates reveal more than you think.

Check the SANs (Subject Alternative Names) on any cert:

echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text | grep DNS:

Often reveals staging servers, internal domains, and dev environments that aren't in scope but lead to in-scope vulnerabilities.`,

  // Tech detection tip
  `How to fingerprint any website's tech stack in 5 seconds:

1. Check response headers: Server, X-Powered-By, X-Generator
2. View source: look for wp-content/, __NEXT_DATA__, __vue, ng-
3. Check /wp-login.php, /admin, /elmah.axd

Knowing the stack tells you which CVEs to look for first.

WordPress → wp-scan
React → prototype pollution
Java/Spring → actuator endpoints
ASP.NET → elmah.axd, trace.axd`,

  // Subdomain takeover
  `Subdomain takeovers are free money if you know where to look.

Check: dig CNAME target.example.com

If it points to:
- *.herokuapp.com (app deleted)
- *.github.io (repo deleted)
- *.azurewebsites.net (app deleted)
- *.amazonaws.com (S3 bucket deleted)

That's a takeover. Register the service, claim the subdomain, report it.

$150-$500 bounties for 5 minutes of work.`,

  // Open redirect
  `Open redirects are underrated.

Check for these patterns:
- /redirect?url=https://evil.com
- /login?next=https://evil.com
- /logout?return=https://evil.com

Test: change the URL parameter to your domain.

If it redirects, that's phishing potential. Some programs pay $250+ for this.

Bypass filters with:
- https://evil.com@target.com
- https://target.com.evil.com
- //evil.com`,

  // API key hunting
  `Found 3 API keys in JavaScript files today.

How to find them:
1. Download all JS files: wget -r -l1 -H -t1 -nd -N -np -A.js https://target.com
2. grep -r "api_key\|apikey\|api-key\|secret\|token\|password" *.js
3. Check for AWS keys: grep -r "AKIA" *.js

Exposed API keys = critical severity = $1000+ bounties.

Always check the JS files.`,

  // Security score tip
  `If you had to check ONE thing on any website, check CORS.

curl -sI -H "Origin: https://evil.com" https://target.com | grep access-control-allow-origin

If it reflects "evil.com" — that's a vulnerability.
If it shows "*" — that's a misconfiguration.

Both are reportable. Both are common. Both are often missed.`,

  // Practical advice
  `Bug bounty advice nobody gives you:

Stop chasing critical RCEs on hardened targets.

Instead:
1. Find programs with wide scope (*.company.com)
2. Enumerate subdomains (usually 50-500)
3. Check for misconfigs on forgotten subdomains

The money is in the subdomains nobody looks at, not the main app everyone tests.`
];

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE)); } catch { return { lastTweet: 0, index: 0 }; }
}
function saveState(state) {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function encode(s) { return encodeURIComponent(s); }
function oauthSign(method, url, params) {
  const sorted = Object.keys(params).sort().map(k => encode(k) + '=' + encode(params[k])).join('&');
  const base = method + '&' + encode(url) + '&' + encode(sorted);
  const key = encode(CS) + '&' + encode(ATS);
  return crypto.createHmac('sha1', key).update(base).digest('base64');
}

function postTweet(text) {
  return new Promise((resolve, reject) => {
    const url = 'https://api.twitter.com/1.1/statuses/update.json';
    const oauth = {
      oauth_consumer_key: CK,
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_token: AT,
      oauth_version: '1.0',
      status: text
    };
    oauth.oauth_signature = oauthSign('POST', url, oauth);
    const auth = 'OAuth ' + Object.keys(oauth).filter(k => k.startsWith('oauth_')).sort().map(k => encode(k) + '="' + encode(oauth[k]) + '"').join(', ');
    const body = 'status=' + encodeURIComponent(text);
    const req = https.request(url, {
      method: 'POST',
      headers: {
        'Authorization': auth,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); } catch { resolve({ error: d }); }
      });
    });
    req.write(body);
    req.end();
  });
}

async function main() {
  const state = loadState();
  const now = Date.now();
  const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;

  if (now - state.lastTweet < TWENTY_FOUR_HOURS) {
    const hoursLeft = Math.ceil((TWENTY_FOUR_HOURS - (now - state.lastTweet)) / (60 * 60 * 1000));
    console.log(`[AutoTweet] Next tweet in ~${hoursLeft} hours`);
    return;
  }

  const tweetText = TWEETS[state.index % TWEETS.length];
  console.log(`[AutoTweet] Posting tweet #${state.index + 1}/${TWEETS.length}...`);

  const result = await postTweet(tweetText);

  if (result.id_str) {
    console.log(`[AutoTweet] SUCCESS! https://x.com/DanDeBot/status/${result.id_str}`);
    state.lastTweet = now;
    state.index = (state.index + 1) % TWEETS.length;
    saveState(state);
  } else if (result.errors) {
    const err = result.errors[0];
    console.log(`[AutoTweet] Error ${err.code}: ${err.message}`);
  } else {
    console.log('[AutoTweet] Unknown:', JSON.stringify(result).slice(0, 200));
  }
}

main();
