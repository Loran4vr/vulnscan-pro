// VulnScan Pro — Database (SQLite)
// Privacy-respecting: only stores what's needed for orders
const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'vulnscan.db');
const db = new Database(DB_PATH);

// WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    tier TEXT NOT NULL,
    actual_tier TEXT,
    target TEXT,
    status TEXT DEFAULT 'pending',
    txid TEXT,
    paid_sats INTEGER DEFAULT 0,
    report_path TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    notes TEXT
  );

  CREATE TABLE IF NOT EXISTS scan_credits (
    chat_id INTEGER NOT NULL,
    credit_type TEXT NOT NULL,  -- 'free', 'pro_trial', 'basic', 'pro', 'elite'
    used INTEGER DEFAULT 0,
    max_allowed INTEGER DEFAULT 0,
    PRIMARY KEY (chat_id, credit_type)
  );

  CREATE INDEX IF NOT EXISTS idx_orders_chat ON orders(chat_id);
  CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
  CREATE INDEX IF NOT EXISTS idx_orders_txid ON orders(txid);
`);

// === PREPARED STATEMENTS ===
const stmts = {
  // Orders
  createOrder: db.prepare(`INSERT INTO orders (chat_id, tier, actual_tier, status) VALUES (?, ?, ?, 'pending')`),
  getOrder: db.prepare(`SELECT * FROM orders WHERE chat_id = ? AND status NOT IN ('complete','cancelled') ORDER BY id DESC LIMIT 1`),
  updateOrder: db.prepare(`UPDATE orders SET status = ?, target = ?, txid = ?, paid_sats = ?, actual_tier = ? WHERE id = ?`),
  completeOrder: db.prepare(`UPDATE orders SET status = 'complete', report_path = ?, completed_at = datetime('now') WHERE id = ?`),
  cancelOrder: db.prepare(`UPDATE orders SET status = 'cancelled' WHERE id = ?`),
  getOrders: db.prepare(`SELECT * FROM orders WHERE chat_id = ? ORDER BY id DESC LIMIT 10`),
  getAllOrders: db.prepare(`SELECT * FROM orders WHERE status = 'complete' ORDER BY completed_at DESC`),
  
  // Credits
  getCredit: db.prepare(`SELECT * FROM scan_credits WHERE chat_id = ? AND credit_type = ?`),
  initCredit: db.prepare(`INSERT OR IGNORE INTO scan_credits (chat_id, credit_type, used, max_allowed) VALUES (?, ?, 0, ?)`),
  useCredit: db.prepare(`UPDATE scan_credits SET used = used + 1 WHERE chat_id = ? AND credit_type = ? AND used < max_allowed`),
  getUsedCount: db.prepare(`SELECT used FROM scan_credits WHERE chat_id = ? AND credit_type = ?`),
  
  // Stats
  totalOrders: db.prepare(`SELECT COUNT(*) as count FROM orders WHERE status = 'complete'`),
  totalRevenue: db.prepare(`SELECT COALESCE(SUM(paid_sats), 0) as total FROM orders WHERE status = 'complete' AND paid_sats > 0`),
  recentOrders: db.prepare(`SELECT * FROM orders WHERE status = 'complete' ORDER BY completed_at DESC LIMIT 20`),
};

// === FUNCTIONS ===
function createOrder(chatId, tier, actualTier) {
  const result = stmts.createOrder.run(chatId, tier, actualTier || tier);
  return result.lastInsertRowid;
}

function getOrder(chatId) {
  return stmts.getOrder.get(chatId);
}

function updateOrder(orderId, data) {
  stmts.updateOrder.run(data.status, data.target, data.txid, data.paid_sats || 0, data.actualTier, orderId);
}

function completeOrder(orderId, reportPath) {
  stmts.completeOrder.run(reportPath, orderId);
}

function cancelOrder(orderId) {
  stmts.cancelOrder.run(orderId);
}

function getOrders(chatId) {
  return stmts.getOrders.all(chatId);
}

// Credits
function initCredits(chatId) {
  // Free tier: 3 scans
  stmts.initCredit.run(chatId, 'free', 3);
  // Pro trial: 1 scan
  stmts.initCredit.run(chatId, 'pro_trial', 1);
}

function canUseCredit(chatId, creditType) {
  initCredits(chatId); // ensure exists
  const row = stmts.getCredit.get(chatId, creditType);
  return row && row.used < row.max_allowed;
}

function useCredit(chatId, creditType) {
  return stmts.useCredit.run(chatId, creditType);
}

function getUsedCount(chatId, creditType) {
  initCredits(chatId);
  const row = stmts.getCredit.get(chatId, creditType);
  return row ? row.used : 0;
}

// Stats (admin)
function getStats() {
  return {
    totalOrders: stmts.totalOrders.get().count,
    totalRevenue: stmts.totalRevenue.get().total,
    recentOrders: stmts.recentOrders.all(),
  };
}

module.exports = {
  db, createOrder, getOrder, updateOrder, completeOrder, cancelOrder, getOrders,
  initCredits, canUseCredit, useCredit, getUsedCount, getStats
};
