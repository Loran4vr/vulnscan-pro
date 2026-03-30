#!/usr/bin/env bash
# VulnScan Pro - Automated Security Scanner
# Usage: ./scanner.sh <target_domain> <tier> <output_dir>
set -uo pipefail

TARGET="${1:?Usage: ./scanner.sh <target> <tier> <output_dir>}"
TIER="${2:-basic}"
OUTDIR="${3:-/root/.openclaw/workspace/vulnscan-pro/reports/$(date +%Y%m%d_%H%M%S)_${TARGET}}"

mkdir -p "$OUTDIR"
LOG="$OUTDIR/scan.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Tier limits
case "$TIER" in
    basic)  MAX_SUBS=100; MAX_LIVE=10;  MAX_CHECK=5  ;;
    pro)    MAX_SUBS=300; MAX_LIVE=25;  MAX_CHECK=15 ;;
    elite)  MAX_SUBS=500; MAX_LIVE=50;  MAX_CHECK=30 ;;
esac

log "=== VulnScan Pro ==="
log "Target: $TARGET | Tier: $TIER | Output: $OUTDIR"

# Phase 1: Subdomain Enumeration
log "[1/6] Enumerating subdomains..."
if command -v subfinder &>/dev/null; then
    subfinder -d "$TARGET" -silent -timeout 60 -max-time 120 -o "$OUTDIR/subdomains_raw.txt" 2>>"$LOG" || true
fi
# Always include main domain
echo "$TARGET" >> "$OUTDIR/subdomains_raw.txt" 2>/dev/null
echo "www.$TARGET" >> "$OUTDIR/subdomains_raw.txt" 2>/dev/null
head -$MAX_SUBS "$OUTDIR/subdomains_raw.txt" 2>/dev/null > "$OUTDIR/subdomains.txt" || true
sort -u "$OUTDIR/subdomains.txt" -o "$OUTDIR/subdomains.txt"
SUBS=$(wc -l < "$OUTDIR/subdomains.txt" 2>/dev/null || echo 0)
log "Found $SUBS subdomains"

# Phase 2: Live Host Detection
log "[2/6] Checking live hosts..."
if command -v httpx &>/dev/null; then
    head -$MAX_LIVE "$OUTDIR/subdomains.txt" | httpx -silent -timeout 5 -threads 30 \
        -o "$OUTDIR/live-hosts.txt" 2>>"$LOG" || true
fi
LIVE=$(wc -l < "$OUTDIR/live-hosts.txt" 2>/dev/null || echo 0)
log "Found $LIVE live hosts"

# Phase 3: Port Scanning (pro/elite only)
if [[ "$TIER" == "pro" || "$TIER" == "elite" ]]; then
    log "[3/6] Scanning common ports..."
    > "$OUTDIR/ports.txt"
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        clean_host=$(echo "$host" | sed 's|https\?://||;s|/.*||')
        for port in 80 443 8080 8443 3000 5000 9090; do
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
                "https://${clean_host}:${port}/" 2>/dev/null || echo "000")
            if [ "$code" != "000" ]; then
                echo "${clean_host}:${port} -> HTTP $code" >> "$OUTDIR/ports.txt"
            fi
        done
    done < "$OUTDIR/live-hosts.txt"
else
    log "[3/6] Port scan (pro/elite tier only)"
fi

# Phase 4: Sensitive File Check
log "[4/6] Checking for exposed sensitive files..."
> "$OUTDIR/sensitive-files.txt"
CHECK_COUNT=0
while IFS= read -r url; do
    [ -z "$url" ] && continue
    [ $CHECK_COUNT -ge $MAX_CHECK ] && break
    CHECK_COUNT=$((CHECK_COUNT + 1))
    for path in ".git/config" ".env" ".env.bak" ".env.local" \
                "wp-config.php.bak" ".DS_Store" "server-status" \
                "elmah.axd" "actuator" "actuator/health" \
                "actuator/env" "debug/pprof" "wp-login.php" \
                "admin" "administrator" "phpinfo.php" ".htaccess"; do
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            "${url}/${path}" 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then
            content=$(curl -s --max-time 5 "${url}/${path}" 2>/dev/null | head -c 300)
            if ! echo "$content" | grep -qi "blocked\|rejected\|unauthorized request\|attention required\|request rejected"; then
                echo "[${code}] ${url}/${path}" >> "$OUTDIR/sensitive-files.txt"
            fi
        fi
    done
done < "$OUTDIR/live-hosts.txt"
SENSITIVE=$(wc -l < "$OUTDIR/sensitive-files.txt" 2>/dev/null || echo 0)
log "Found $SENSITIVE exposed sensitive files"

# Phase 5: CORS & Security Headers
log "[5/6] Checking CORS and security headers..."
> "$OUTDIR/cors-issues.txt"
> "$OUTDIR/security-headers.txt"
CHECK_COUNT=0
while IFS= read -r url; do
    [ -z "$url" ] && continue
    [ $CHECK_COUNT -ge $MAX_CHECK ] && break
    CHECK_COUNT=$((CHECK_COUNT + 1))
    
    cors=$(curl -s -I --max-time 5 -H "Origin: https://evil.com" "$url" 2>/dev/null \
        | grep -i "access-control-allow-origin" | tr -d '\r')
    if [ -n "$cors" ]; then
        if echo "$cors" | grep -q "evil.com"; then
            echo "$url -> $cors [VULNERABLE]" >> "$OUTDIR/cors-issues.txt"
        elif echo "$cors" | grep -q "\*"; then
            echo "$url -> $cors [WILDCARD]" >> "$OUTDIR/cors-issues.txt"
        fi
    fi
    
    headers=$(curl -s -I --max-time 5 "$url" 2>/dev/null | tr -d '\r')
    missing=""
    for h in "X-Frame-Options" "Content-Security-Policy" \
             "Strict-Transport-Security" "X-Content-Type-Options"; do
        if ! echo "$headers" | grep -qi "$h"; then
            missing="${missing}${h}, "
        fi
    done
    if [ -n "$missing" ]; then
        echo "$url -> Missing: ${missing%, }" >> "$OUTDIR/security-headers.txt"
    fi
done < "$OUTDIR/live-hosts.txt"

# Phase 6: Nuclei Scan (pro/elite only)
if [[ "$TIER" == "pro" || "$TIER" == "elite" ]]; then
    log "[6/6] Running nuclei vulnerability scan..."
    if command -v nuclei &>/dev/null && [ -f "$OUTDIR/live-hosts.txt" ]; then
        nuclei -l "$OUTDIR/live-hosts.txt" \
            -severity critical,high,medium \
            -type http -timeout 8 -retries 1 \
            -c 15 -rl 30 \
            -o "$OUTDIR/nuclei-results.txt" \
            -silent 2>>"$LOG" || true
    fi
else
    log "[6/6] Nuclei scan (pro/elite tier only)"
fi

# Generate Report
log "Generating report..."
cat > "$OUTDIR/REPORT.md" << REPORT
# VulnScan Pro - Security Assessment Report

**Target:** $TARGET
**Tier:** $(echo $TIER | tr '[:lower:]' '[:upper:]')
**Date:** $(date -u '+%Y-%m-%d %H:%M UTC')
**Scanner:** VulnScan Pro v1.0

---

## Summary

| Metric | Count |
|--------|-------|
| Subdomains discovered | $SUBS |
| Live hosts | $LIVE |
| Sensitive files exposed | $SENSITIVE |
| CORS issues | $(wc -l < "$OUTDIR/cors-issues.txt" 2>/dev/null || echo 0) |

## Live Hosts

$(cat "$OUTDIR/live-hosts.txt" 2>/dev/null | sed 's/^/- /')

## Sensitive Files Exposed

$(if [ "$SENSITIVE" -gt 0 ]; then
    cat "$OUTDIR/sensitive-files.txt" 2>/dev/null | sed 's/^/- /'
else
    echo "No exposed sensitive files found."
fi)

## CORS Misconfigurations

$(if [ -s "$OUTDIR/cors-issues.txt" ]; then
    cat "$OUTDIR/cors-issues.txt" 2>/dev/null | sed 's/^/- /'
else
    echo "No CORS issues detected."
fi)

## Missing Security Headers

$(if [ -s "$OUTDIR/security-headers.txt" ]; then
    head -30 "$OUTDIR/security-headers.txt" 2>/dev/null | sed 's/^/- /'
else
    echo "All security headers present."
fi)

$(if [ -f "$OUTDIR/nuclei-results.txt" ]; then
echo "## Nuclei Vulnerability Findings"
echo ""
cat "$OUTDIR/nuclei-results.txt" 2>/dev/null | sed 's/^/- /'
fi)

---

*Report generated by VulnScan Pro - Automated Security Recon*
REPORT

log "Report saved to $OUTDIR/REPORT.md"
log "=== Scan Complete ==="

echo "$OUTDIR"
