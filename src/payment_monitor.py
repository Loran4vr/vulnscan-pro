#!/usr/bin/env python3
"""
VulnScan Pro - BTC Payment Monitor
Checks blockchain for incoming payments and triggers delivery.
Uses Blockstream's free Esplora API (no key needed).
"""

import json
import time
import os
import sys
import subprocess
import hashlib
from urllib.request import urlopen, Request
from datetime import datetime

# === CONFIG ===
BTC_ADDRESS = "1BL4eV82zZ64Dp4cj3s9EgJ3ae8xPx5ZuJ"
PRICES = {
    "basic": 0.0003,    # ~$25 at $83k/BTC - single target scan
    "pro": 0.0012,      # ~$100 - 5 targets + full report
    "elite": 0.0024,    # ~$200 - 10 targets + priority + custom
}
STATE_FILE = "/root/.openclaw/workspace/vulnscan-pro/data/payments.json"
API_BASE = "https://blockstream.info/api"

# Map price tiers to scan commands
TIER_CONFIG = {
    "basic": {"targets": 1, "depth": "standard"},
    "pro": {"targets": 5, "depth": "deep"},
    "elite": {"targets": 10, "depth": "comprehensive"},
}

def load_state():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"seen_txids": [], "processed": [], "balance_sats": 0}

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def check_transactions():
    """Fetch recent transactions for our address."""
    try:
        url = f"{API_BASE}/address/{BTC_ADDRESS}/txs"
        req = Request(url, headers={"User-Agent": "VulnScanPro/1.0"})
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[ERROR] Failed to fetch transactions: {e}")
        return []

def get_confirmed_balance():
    """Get current confirmed balance in satoshis."""
    try:
        url = f"{API_BASE}/address/{BTC_ADDRESS}"
        req = Request(url, headers={"User-Agent": "VulnScanPro/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data["chain_stats"]["funded_txo_sum"]
    except Exception as e:
        print(f"[ERROR] Failed to check balance: {e}")
        return 0

def classify_payment(sats):
    """Determine tier based on satoshi amount."""
    if sats >= int(PRICES["elite"] * 1e8):
        return "elite"
    elif sats >= int(PRICES["pro"] * 1e8):
        return "pro"
    elif sats >= int(PRICES["basic"] * 1e8):
        return "basic"
    return None

def extract_order_memo(op_return_outputs):
    """Try to extract order info from OP_RETURN if present."""
    # Customers can embed target domain in OP_RETURN
    # For now, we'll handle orders via a separate form
    return None

def process_incoming_payment(txid, sats, confirmations):
    """Process a new incoming payment."""
    tier = classify_payment(sats)
    if not tier:
        print(f"[INFO] Payment of {sats} sats doesn't match any tier (tx: {txid[:16]}...)")
        return None
    
    print(f"[PAYMENT] {tier.upper()} tier detected: {sats} sats (tx: {txid[:16]}...)")
    return {
        "txid": txid,
        "sats": sats,
        "tier": tier,
        "confirmations": confirmations,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "pending_target"  # Waiting for customer to provide target
    }

def main():
    print(f"=== VulnScan Pro Payment Monitor ===")
    print(f"Address: {BTC_ADDRESS}")
    print(f"Checking for payments...\n")
    
    state = load_state()
    
    # Check balance first (faster)
    balance = get_confirmed_balance()
    print(f"Current balance: {balance} sats ({balance/1e8:.8f} BTC)")
    
    if balance > state["balance_sats"]:
        delta = balance - state["balance_sats"]
        print(f"New funds detected: +{delta} sats")
        tier = classify_payment(delta)
        if tier:
            print(f"  -> Matches {tier.upper()} tier!")
        state["balance_sats"] = balance
        save_state(state)
    
    # Check individual transactions
    txs = check_transactions()
    new_payments = []
    
    for tx in txs:
        txid = tx["txid"]
        if txid in state["seen_txids"]:
            continue
        
        # Calculate incoming value to our address
        incoming = 0
        for vout in tx.get("vout", []):
            if vout.get("scriptpubkey_address") == BTC_ADDRESS:
                incoming += vout["value"]
        
        confirmations = tx.get("status", {}).get("block_height", 0)
        if confirmations:
            current_height = 0  # Would need to fetch
            confirmations = max(1, confirmations)  # Simplified
        
        if incoming > 0:
            payment = process_incoming_payment(txid, incoming, confirmations)
            if payment:
                new_payments.append(payment)
                state["processed"].append(payment)
        
        state["seen_txids"].append(txid)
    
    save_state(state)
    
    if new_payments:
        print(f"\n{'='*50}")
        print(f"NEW PAYMENTS: {len(new_payments)}")
        for p in new_payments:
            print(f"  {p['tier'].upper()}: {p['sats']} sats - txid: {p['txid'][:32]}...")
        print(f"{'='*50}")
    else:
        print("\nNo new payments found.")
    
    # Show pending orders
    pending = [p for p in state["processed"] if p["status"] == "pending_target"]
    if pending:
        print(f"\nPending orders (waiting for target): {len(pending)}")
    
    return new_payments

if __name__ == "__main__":
    if "--daemon" in sys.argv:
        print("Running in daemon mode (check every 60s)...")
        while True:
            main()
            time.sleep(60)
    else:
        main()
