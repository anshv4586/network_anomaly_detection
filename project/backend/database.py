import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "database.sqlite"))

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Create prediction history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        mode TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        dst_port INTEGER,
        prediction INTEGER,
        confidence REAL,
        attack_type TEXT,
        if_score REAL,
        xgb_prob REAL,
        shap_explanation TEXT
    )
    """)
    
    # 2. Create settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    
    # 3. Create logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        message TEXT
    )
    """)
    
    # Insert default settings if they don't exist
    default_settings = {
        "context_window": "30",
        "model_selection": "Hybrid Model",
        "confidence_threshold": "0.5",
        "packet_capture_interface": "",
        "auto_refresh": "true",
        "dark_mode": "true"
    }
    
    for key, val in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))
        
    conn.commit()
    conn.close()
    add_log("INFO", "Database initialized successfully.")

def add_log(level, message):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)", (timestamp, level, message))
    conn.commit()
    conn.close()

def get_logs(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, level, message FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    rows = cursor.fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}

def save_setting(key, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
    add_log("INFO", f"Setting '{key}' updated to '{value}'.")

def get_setting(key, default=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["value"]
    return default

def add_prediction(mode, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, xgb_prob, shap_explanation):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # shap_explanation is expected to be a list/dict, dump to json string
    shap_str = json.dumps(shap_explanation) if isinstance(shap_explanation, (list, dict)) else str(shap_explanation)
    
    cursor.execute("""
    INSERT INTO history (timestamp, mode, src_ip, dst_ip, protocol, dst_port, prediction, confidence, attack_type, if_score, xgb_prob, shap_explanation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, mode, src_ip, dst_ip, protocol, dst_port, int(prediction), float(confidence), attack_type, float(if_score), float(xgb_prob), shap_str))
    
    conn.commit()
    conn.close()

def get_history(search=None, mode=None, prediction=None, protocol=None, limit=100, offset=0, sort_by="timestamp", sort_order="DESC"):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM history WHERE 1=1"
    params = []
    
    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
        
    if mode:
        query += " AND mode = ?"
        params.append(mode)
        
    if prediction is not None:
        query += " AND prediction = ?"
        params.append(int(prediction))
        
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)
        
    # Guard against SQL injection in sorting fields since they can't be parameterized directly
    allowed_sort_cols = ["timestamp", "mode", "src_ip", "dst_ip", "protocol", "dst_port", "prediction", "confidence", "attack_type"]
    if sort_by not in allowed_sort_cols:
        sort_by = "timestamp"
    if sort_order.upper() not in ["ASC", "DESC"]:
        sort_order = "DESC"
        
    query += f" ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Get total count for pagination
    count_query = "SELECT COUNT(*) as count FROM history WHERE 1=1"
    count_params = []
    if search:
        count_query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)"
        count_params.extend([search_param, search_param, search_param])
    if mode:
        count_query += " AND mode = ?"
        count_params.append(mode)
    if prediction is not None:
        count_query += " AND prediction = ?"
        count_params.append(int(prediction))
    if protocol:
        count_query += " AND protocol = ?"
        count_params.append(protocol)
        
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()["count"]
    
    conn.close()
    
    results = []
    for row in rows:
        r = dict(row)
        try:
            r["shap_explanation"] = json.loads(r["shap_explanation"])
        except Exception:
            pass
        results.append(r)
        
    return results, total_count
