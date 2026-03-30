#!/usr/bin/env node
// VulnScan Pro — Tweet Monitor
// Checks tweet status and engagement (uses minimal API credits)
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');

const CK = 'asXLiYQEGCUM5rfdWNms7hcMb';
const CS = '0jZfxOeDElxIxXQ8yAZhTXqX7D8ZZdPon90sWShu9wQuxR3gnw';
const AT = '2038610379366903809-pjv6HX1NoIwYmKljfmK9QQJFZxuko6';
const ATS = 'hEkxt8migXDFSdzAd80Ffx9DtDr2OzbNaEGEIml7wxPy1';

const STATE_FILE = path.join(__dirname, 'data', 'tweet_state.json');
const LOG_FILE = path.join(__dirname, 'data', 'tweet_monitor.log');

function encode(s) { return encodeURIComponent(s); }
function oauthSign(method, url, params) {
  const sorted = Object.keys(params).sort().map(k => encode(k) + '=' + encode(params[k])).join('&');
  const base = method + '&' + encode(url) + '&' + encode(sorted);
  const key = encode(CS) + '&' + encode(ATS);
  return crypto.createHmac('sha1', key).update(base).digest('base64');
}

function apiGet(endpoint, params = {}) {
  return new Promise((resolve) => {
    const baseUrl = 'https://api.twitter.com/1.1' + endpoint;
    const oauth = {
      oauth_consumer_key: CK,
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_token: AT,
      oauth_version: '1.0',
      ...params
    };
    oauth.oauth_signature = oauthSign('GET', baseUrl, oauth);
    const auth = 'OAuth ' + Object.keys(oauth).filter(k => k.startsWith('oauth_')).sort().map(k => encode(k) + '="' + encode(oauth[k]) + '"').join(', ');
    
    const queryStr = Object.keys(params).map(k => encode(k) + '=' + encode(params[k])).join('&');
    const fullUrl = baseUrl + (queryStr ? '?' + queryStr : '');
    
    https.get(fullUrl, { headers: { 'Authorization': auth } }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); } catch { resolve({ raw: d.slice(0, 300) }); }
      });
    }).on('error', () => resolve({ error: 'network' }));
  });
}

async function checkProfile() {
  // 1 API call - get own profile
  const profile = await apiGet('/account/verify_credentials.json');
  if (profile.screen_name) {
    return {
      handle: profile.screen_name,
      followers: profile.followers_count,
      following: profile.friends_count,
      tweets: profile.statuses_count,
      created: profile.created_at
    };
  }
  return { error: profile.errors?.[0]?.message || 'unknown' };
}

async function getRecentTweets(count = 5) {
  // 1 API call - get recent tweets
  const tweets = await apiGet('/statuses/user_timeline.json', { count: count.toString(), trim_user: 'true' });
  if (Array.isArray(tweets)) {
    return tweets.map(t => ({
      id: t.id_str,
      text: t.text.slice(0, 80) + (t.text.length > 80 ? '...' : ''),
      date: t.created_at,
      retweets: t.retweet_count,
      likes: t.favorite_count,
      replies: t.reply_count || 0
    }));
  }
  return { error: tweets.errors?.[0]?.message || 'unknown' };
}

async function getMentions(count = 5) {
  // 1 API call - check mentions
  const mentions = await apiGet('/statuses/mentions_timeline.json', { count: count.toString() });
  if (Array.isArray(mentions)) {
    return mentions.map(m => ({
      from: '@' + m.user.screen_name,
      text: m.text.slice(0, 80),
      date: m.created_at
    }));
  }
  return { error: mentions.errors?.[0]?.message || 'unknown' };
}

async function main() {
  console.log('=== VulnScan Pro Tweet Monitor ===\n');
  
  // Check state
  let state = {};
  try { state = JSON.parse(fs.readFileSync(STATE_FILE)); } catch {}
  
  const now = Date.now();
  const hoursSinceLastTweet = state.lastTweet ? Math.floor((now - state.lastTweet) / (60 * 60 * 1000)) : 'never';
  
  console.log(`Last tweet: ${hoursSinceLastTweet}h ago`);
  console.log(`Next tweet index: ${(state.index || 0) + 1}/12`);
  console.log(`Auto-tweet: ${now - (state.lastTweet || 0) < 86400000 ? 'waiting (posted today)' : 'ready to post'}\n`);
  
  // Check profile (1 API call - works on free tier)
  console.log('Checking profile...');
  const profile = await checkProfile();
  if (profile.handle) {
    console.log(`@${profile.handle} | ${profile.followers} followers | ${profile.tweets} tweets\n`);
  } else {
    console.log(`Profile error: ${JSON.stringify(profile)}\n`);
  }
  
  // Tweet history from local state
  console.log('Tweet history (from local log):');
  const logPath = path.join(__dirname, 'data', 'tweet.log');
  if (fs.existsSync(logPath)) {
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.includes('SUCCESS') || l.includes('Error'));
    for (const l of lines.slice(-5)) {
      console.log(`  ${l}`);
    }
  } else {
    console.log('  No tweet log yet.');
  }
  
  console.log(`\nAPI calls used: 1 (profile only — free tier limits)`);
  console.log('=== Done ===');
}

main();
