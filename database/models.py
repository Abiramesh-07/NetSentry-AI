import json
from datetime import datetime
from database.db import get_db, query_db, execute_db

class UserModel:
    @staticmethod
    def get_by_username(username):
        return query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)

    @staticmethod
    def get_by_id(user_id):
        return query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)

    @staticmethod
    def update_last_login(user_id):
        execute_db("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))

class FlowModel:
    @staticmethod
    def insert(flow_data):
        query = '''
        INSERT INTO network_flows (
            timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
            bytes_sent, bytes_recv, total_bytes, packets_sent, packets_recv,
            duration, outbound_inbound_ratio, flags, service, is_simulated, pcap_filename
        ) VALUES (
            COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?
        )
        '''
        return execute_db(query, (
            flow_data.get('timestamp'),
            flow_data.get('src_ip'),
            flow_data.get('dst_ip'),
            flow_data.get('src_port', 0),
            flow_data.get('dst_port', 0),
            flow_data.get('protocol', 'TCP'),
            flow_data.get('bytes_sent', 0),
            flow_data.get('bytes_recv', 0),
            flow_data.get('total_bytes', flow_data.get('bytes_sent', 0) + flow_data.get('bytes_recv', 0)),
            flow_data.get('packets_sent', 1),
            flow_data.get('packets_recv', 1),
            flow_data.get('duration', 0.1),
            flow_data.get('outbound_inbound_ratio', 0.5),
            flow_data.get('flags', ''),
            flow_data.get('service', 'Unknown'),
            flow_data.get('is_simulated', 0),
            flow_data.get('pcap_filename', None)
        ))

    @staticmethod
    def get_recent(limit=50):
        return query_db('''
        SELECT f.*, p.isolation_score, p.rf_class, p.rf_confidence, a.severity, a.risk_score
        FROM network_flows f
        LEFT JOIN ai_predictions p ON f.id = p.flow_id
        LEFT JOIN security_alerts a ON f.id = a.flow_id
        ORDER BY f.id DESC LIMIT ?
        ''', (limit,))

    @staticmethod
    def get_count():
        res = query_db("SELECT COUNT(*) as count FROM network_flows", one=True)
        return res['count'] if res else 0

class DeviceProfileModel:
    @staticmethod
    def get_or_create(device_ip, hostname=None):
        profile = query_db("SELECT * FROM device_profiles WHERE device_ip = ?", (device_ip,), one=True)
        if not profile:
            execute_db('''
            INSERT INTO device_profiles (device_ip, hostname, total_flows_analyzed, avg_bytes_sent, std_bytes_sent, max_bytes_sent, avg_ratio)
            VALUES (?, COALESCE(?, 'Internal Host'), 1, 50000, 15000, 200000, 0.65)
            ''', (device_ip, hostname))
            profile = query_db("SELECT * FROM device_profiles WHERE device_ip = ?", (device_ip,), one=True)
        return profile

    @staticmethod
    def get_all():
        return query_db("SELECT * FROM device_profiles ORDER BY total_flows_analyzed DESC")

    @staticmethod
    def update_baseline_from_validated_normal(device_ip, new_bytes_sent, new_ratio):
        """Adaptive Behavioral Profiling: updates profile metrics strictly with validated normal traffic."""
        prof = DeviceProfileModel.get_or_create(device_ip)
        count = prof['total_flows_analyzed'] + 1
        old_avg = prof['avg_bytes_sent']
        
        # Incremental moving average and variance
        new_avg = old_avg + (new_bytes_sent - old_avg) / count
        new_max = max(prof['max_bytes_sent'], new_bytes_sent)
        new_ratio_avg = prof['avg_ratio'] * 0.9 + new_ratio * 0.1
        
        execute_db('''
        UPDATE device_profiles
        SET total_flows_analyzed = ?,
            avg_bytes_sent = ?,
            max_bytes_sent = ?,
            avg_ratio = ?,
            baseline_confidence = MIN(0.99, baseline_confidence + 0.01),
            last_updated = CURRENT_TIMESTAMP
        WHERE device_ip = ?
        ''', (count, round(new_avg, 2), new_max, round(new_ratio_avg, 3), device_ip))

class PredictionModel:
    @staticmethod
    def record(flow_id, isolation_score, is_isolation_anomaly, rf_class, rf_confidence, rf_probs, feature_contributions, model_version="v1.0"):
        query = '''
        INSERT INTO ai_predictions (
            flow_id, model_version, isolation_score, is_isolation_anomaly,
            rf_class, rf_confidence, rf_probs_json, feature_contributions_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        return execute_db(query, (
            flow_id,
            model_version,
            round(float(isolation_score), 4),
            1 if is_isolation_anomaly else 0,
            rf_class,
            round(float(rf_confidence), 4),
            json.dumps(rf_probs),
            json.dumps(feature_contributions)
        ))

    @staticmethod
    def get_by_flow(flow_id):
        return query_db("SELECT * FROM ai_predictions WHERE flow_id = ?", (flow_id,), one=True)

class AlertModel:
    @staticmethod
    def create(flow_id, alert_type, severity, risk_score, src_ip, dst_ip, summary):
        query = '''
        INSERT INTO security_alerts (
            flow_id, alert_type, severity, risk_score, src_ip, dst_ip, summary, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'New')
        '''
        alert_id = execute_db(query, (
            flow_id, alert_type, severity, round(float(risk_score), 1), src_ip, dst_ip, summary
        ))
        
        # Automatically create corresponding incident entry
        timeline = [
            {"time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "event": f"System generated {severity} security alert: {alert_type}"},
            {"time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "event": f"Dynamic risk calculated at {round(float(risk_score), 1)}/100"}
        ]
        
        recs = [
            f"Isolate host {src_ip} if suspicious outbound transfer continues",
            f"Review destination IP {dst_ip} reputation and associated domain name",
            "Cross-reference outbound data volume with device historical baseline",
            "Verify whether process running on host has authorized file transfer credentials"
        ]
        
        execute_db('''
        INSERT INTO incidents (alert_id, title, description, incident_timeline_json, recommended_actions_json, status)
        VALUES (?, ?, ?, ?, ?, 'Open')
        ''', (
            alert_id,
            f"{severity.upper()}: {alert_type} from {src_ip}",
            summary,
            json.dumps(timeline),
            json.dumps(recs)
        ))
        return alert_id

    @staticmethod
    def get_recent(limit=50):
        return query_db('''
        SELECT a.*, f.protocol, f.bytes_sent, f.bytes_recv, f.duration, f.service,
               p.isolation_score, p.rf_class, p.feature_contributions_json
        FROM security_alerts a
        JOIN network_flows f ON a.flow_id = f.id
        LEFT JOIN ai_predictions p ON f.id = p.flow_id
        ORDER BY a.id DESC LIMIT ?
        ''', (limit,))

    @staticmethod
    def get_by_id(alert_id):
        return query_db('''
        SELECT a.*, f.protocol, f.bytes_sent, f.bytes_recv, f.duration, f.service, f.outbound_inbound_ratio,
               p.isolation_score, p.rf_class, p.rf_confidence, p.rf_probs_json, p.feature_contributions_json,
               i.id as incident_id, i.incident_timeline_json, i.recommended_actions_json, i.status as incident_status
        FROM security_alerts a
        JOIN network_flows f ON a.flow_id = f.id
        LEFT JOIN ai_predictions p ON f.id = p.flow_id
        LEFT JOIN incidents i ON a.id = i.alert_id
        WHERE a.id = ?
        ''', (alert_id,), one=True)

    @staticmethod
    def update_feedback(alert_id, status, notes):
        """False positive feedback loop: update alert status and analyst notes."""
        execute_db('''
        UPDATE security_alerts
        SET status = ?, analyst_notes = ?, feedback_updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''', (status, notes, alert_id))
        
        # Sync incident status
        inc_status = 'Closed' if status in ('False Positive', 'Resolved') else ('In Progress' if status == 'Under Investigation' else 'Open')
        execute_db('''
        UPDATE incidents
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
        ''', (inc_status, alert_id))

class ThreatIntelModel:
    @staticmethod
    def get_ip(ip_address):
        return query_db("SELECT * FROM threat_intel WHERE ip_address = ?", (ip_address,), one=True)

    @staticmethod
    def upsert(ip, reputation_score, category, country, isp, is_malicious, tags):
        execute_db('''
        INSERT INTO threat_intel (ip_address, reputation_score, category, country, isp, is_known_malicious, tags_json, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(ip_address) DO UPDATE SET
            reputation_score = excluded.reputation_score,
            category = excluded.category,
            country = excluded.country,
            isp = excluded.isp,
            is_known_malicious = excluded.is_known_malicious,
            tags_json = excluded.tags_json,
            last_checked = CURRENT_TIMESTAMP
        ''', (ip, reputation_score, category, country, isp, 1 if is_malicious else 0, json.dumps(tags)))

class SettingsModel:
    @staticmethod
    def get_all():
        rows = query_db("SELECT * FROM application_settings")
        return {r['key']: r['value'] for r in rows}

    @staticmethod
    def get(key, default=None):
        res = query_db("SELECT value FROM application_settings WHERE key = ?", (key,), one=True)
        return res['value'] if res else default

    @staticmethod
    def set(key, value):
        execute_db('''
        INSERT INTO application_settings (key, value, description, updated_at)
        VALUES (?, ?, '', CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        ''', (key, str(value)))
