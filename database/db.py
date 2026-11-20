import sqlite3
import os
import json
from datetime import datetime
from werkzeug.security import generate_password_hash
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=(), commit=True):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    last_id = cur.lastrowid
    if commit:
        conn.commit()
    cur.close()
    conn.close()
    return last_id

def init_db():
    """Initializes the SQLite database with full schema and seed data."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = get_db()
    cur = conn.cursor()

    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS network_flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT NOT NULL,
        bytes_sent INTEGER NOT NULL DEFAULT 0,
        bytes_recv INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER NOT NULL DEFAULT 0,
        packets_sent INTEGER NOT NULL DEFAULT 0,
        packets_recv INTEGER NOT NULL DEFAULT 0,
        duration REAL NOT NULL DEFAULT 0.0,
        outbound_inbound_ratio REAL NOT NULL DEFAULT 0.0,
        flags TEXT DEFAULT '',
        service TEXT DEFAULT 'Unknown',
        is_simulated INTEGER DEFAULT 0,
        pcap_filename TEXT DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS device_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT UNIQUE NOT NULL,
        mac_address TEXT DEFAULT 'Unknown',
        hostname TEXT DEFAULT 'Workstation',
        total_flows_analyzed INTEGER DEFAULT 0,
        avg_bytes_sent REAL DEFAULT 50000.0,
        std_bytes_sent REAL DEFAULT 15000.0,
        max_bytes_sent INTEGER DEFAULT 250000,
        avg_ratio REAL DEFAULT 0.65,
        peak_hour_start INTEGER DEFAULT 9,
        peak_hour_end INTEGER DEFAULT 18,
        baseline_confidence REAL DEFAULT 0.85,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_whitelisted INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS ai_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id INTEGER NOT NULL,
        model_version TEXT DEFAULT 'v1.0-rf-iforest',
        isolation_score REAL NOT NULL,
        is_isolation_anomaly INTEGER NOT NULL DEFAULT 0,
        rf_class TEXT NOT NULL,
        rf_confidence REAL NOT NULL,
        rf_probs_json TEXT NOT NULL,
        feature_contributions_json TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (flow_id) REFERENCES network_flows (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        summary TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        analyst_notes TEXT DEFAULT '',
        feedback_updated_at TIMESTAMP,
        FOREIGN KEY (flow_id) REFERENCES network_flows (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        incident_timeline_json TEXT NOT NULL,
        recommended_actions_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open',
        assigned_to TEXT DEFAULT 'SecOps Team',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (alert_id) REFERENCES security_alerts (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS model_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT NOT NULL,
        version TEXT NOT NULL,
        accuracy REAL NOT NULL,
        precision_score REAL NOT NULL,
        recall_score REAL NOT NULL,
        f1_score REAL NOT NULL,
        confusion_matrix_json TEXT NOT NULL,
        sample_count INTEGER NOT NULL,
        trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        reputation_score INTEGER NOT NULL DEFAULT 0,
        category TEXT DEFAULT 'Clean',
        country TEXT DEFAULT 'US',
        isp TEXT DEFAULT 'Unknown',
        is_known_malicious INTEGER DEFAULT 0,
        tags_json TEXT DEFAULT '[]',
        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS application_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS generated_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        report_type TEXT NOT NULL,
        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT NOT NULL,
        total_incidents INTEGER NOT NULL DEFAULT 0,
        avg_risk_score REAL NOT NULL DEFAULT 0.0,
        download_count INTEGER NOT NULL DEFAULT 0
    );

    -- Performance indexes
    CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows (timestamp);
    CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows (src_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts (timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts (severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts (status);
    ''')

    # Seed default Admin User (admin / admin123)
    cur.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cur.fetchone():
        hashed_pw = generate_password_hash('admin123')
        cur.execute('''
        INSERT INTO users (username, email, password_hash, role)
        VALUES ('admin', 'admin@netsentry.ai', ?, 'SOC Administrator')
        ''', (hashed_pw,))

    # Seed default analyst user (analyst / analyst123)
    cur.execute("SELECT id FROM users WHERE username = 'analyst'")
    if not cur.fetchone():
        hashed_pw = generate_password_hash('analyst123')
        cur.execute('''
        INSERT INTO users (username, email, password_hash, role)
        VALUES ('analyst', 'analyst@netsentry.ai', ?, 'Security Analyst')
        ''', (hashed_pw,))

    # Seed Application Settings
    default_settings = [
        ('isolation_weight', '0.30', 'Weight of Isolation Forest Anomaly Score in Risk Calculation'),
        ('rf_weight', '0.30', 'Weight of Random Forest Prediction Probability in Risk Calculation'),
        ('behavior_weight', '0.20', 'Weight of Adaptive Behavioral Deviation in Risk Calculation'),
        ('volume_weight', '0.10', 'Weight of Outbound Volume Anomaly in Risk Calculation'),
        ('reputation_weight', '0.10', 'Weight of Destination Threat Intelligence in Risk Calculation'),
        ('anomaly_threshold', '0.60', 'Sensitivity threshold for Isolation Forest anomaly flagging'),
        ('virustotal_api_key', '', 'VirusTotal API key for live threat intel queries'),
        ('abuseipdb_api_key', '', 'AbuseIPDB API key for IP reputation checks'),
        ('sim_stream_active', '1', 'Simulated Live Stream state (1=Active, 0=Paused)'),
        ('sim_stream_speed', '1.0', 'Live simulation feed playback speed factor')
    ]

    for key, val, desc in default_settings:
        cur.execute("SELECT key FROM application_settings WHERE key = ?", (key,))
        if not cur.fetchone():
            cur.execute("INSERT INTO application_settings (key, value, description) VALUES (?, ?, ?)", (key, val, desc))

    conn.commit()
    cur.close()
    conn.close()
    print("NetSentry AI SQLite Database successfully initialized with tables and seed configurations.")

if __name__ == '__main__':
    init_db()
