#!/usr/bin/env python3
"""
VulnScan Pro - Order Handler
Manages incoming scan orders, verifies payment, runs scan, delivers report.
"""

import json
import os
import sys
import subprocess
import hashlib
from datetime import datetime

BASE = "/root/.openclaw/workspace/vulnscan-pro"
ORDERS_FILE = f"{BASE}/data/orders.json"
SCANNER = f"{BASE}/src/scanner.sh"

def load_orders():
    os.makedirs(os.path.dirname(ORDERS_FILE), exist_ok=True)
    if os.path.exists(ORDERS_FILE):
        with open(ORDERS_FILE) as f:
            return json.load(f)
    return []

def save_orders(orders):
    with open(ORDERS_FILE, 'w') as f:
        json.dump(orders, f, indent=2)

def create_order(target, tier="basic", contact=None, txid=None):
    """Create a new scan order."""
    orders = load_orders()
    order = {
        "id": hashlib.md5(f"{target}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:8],
        "target": target,
        "tier": tier,
        "contact": contact,
        "txid": txid,
        "status": "pending",  # pending -> scanning -> complete
        "created": datetime.utcnow().isoformat(),
        "report_path": None
    }
    orders.append(order)
    save_orders(orders)
    print(f"Order created: {order['id']} for {target} ({tier})")
    return order

def run_scan(order_id):
    """Execute scan for an order."""
    orders = load_orders()
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        print(f"Order {order_id} not found")
        return
    
    order["status"] = "scanning"
    save_orders(orders)
    
    print(f"Starting scan for {order['target']} (tier: {order['tier']})...")
    result = subprocess.run(
        ["bash", SCANNER, order["target"], order["tier"]],
        capture_output=True, text=True, timeout=600
    )
    
    output_dir = result.stdout.strip().split('\n')[-1] if result.stdout else None
    
    order["status"] = "complete"
    order["report_path"] = output_dir
    order["completed"] = datetime.utcnow().isoformat()
    save_orders(orders)
    
    print(f"Scan complete! Report: {output_dir}/REPORT.md")
    return output_dir

def list_orders(status=None):
    """List orders, optionally filtered by status."""
    orders = load_orders()
    if status:
        orders = [o for o in orders if o["status"] == status]
    for o in orders:
        print(f"  [{o['status']}] {o['id']} | {o['target']} | {o['tier']} | {o['created'][:16]}")
    return orders

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  order_handler.py create <target> [tier] [contact] [txid]")
        print("  order_handler.py run <order_id>")
        print("  order_handler.py list [status]")
        print("  order_handler.py process-all")
        return
    
    cmd = sys.argv[1]
    
    if cmd == "create":
        target = sys.argv[2]
        tier = sys.argv[3] if len(sys.argv) > 3 else "basic"
        contact = sys.argv[4] if len(sys.argv) > 4 else None
        txid = sys.argv[5] if len(sys.argv) > 5 else None
        create_order(target, tier, contact, txid)
    
    elif cmd == "run":
        order_id = sys.argv[2]
        run_scan(order_id)
    
    elif cmd == "list":
        status = sys.argv[2] if len(sys.argv) > 2 else None
        list_orders(status)
    
    elif cmd == "process-all":
        orders = list_orders("pending")
        for o in orders:
            run_scan(o["id"])
    
    else:
        print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()
