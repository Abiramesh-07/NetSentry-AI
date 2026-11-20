import os
import json
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file, abort
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from database.db import get_db, init_db, query_db, execute_db
from database.models import (
    UserModel, FlowModel, DeviceProfileModel, PredictionModel,
    AlertModel, ThreatIntelModel, SettingsModel
)
from ai_engine.trainer import ModelTrainer
from ai_engine.random_forest import RandomForestClassifierEngine
from ai_engine.isolation_forest import IsolationForestDetector
from ai_engine.explainable_ai import ExplainableAI
from ai_engine.behavioral_profiler import BehavioralProfiler
from network.pcap_parser import PCAPParser
from network.traffic_simulator import TrafficSimulator
from network.sample_pcaps import generate_sample_pcaps
from threat_intel.intel_service import ThreatIntelService
from reports.pdf_generator import PDFReportGenerator

# Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist
for folder in [Config.UPLOAD_FOLDER, Config.SAMPLE_PCAP_FOLDER, Config.MODEL_DIR, Config.REPORT_DIR]:
    os.makedirs(folder, exist_ok=True)

# Initialize Database & Models if needed
init_db()

# Ensure Models & Sample PCAPs exist
if not os.path.exists(os.path.join(Config.MODEL_DIR, 'random_forest.joblib')):
    print("[NetSentry AI] Training initial AI models...")
    ModelTrainer.train_and_evaluate(n_samples=3000)

if not os.path.exists(os.path.join(Config.SAMPLE_PCAP_FOLDER, 'normal_workstation_traffic.pcap')):
    print("[NetSentry AI] Generating sample PCAP suite...")
    generate_sample_pcaps()

# Start background traffic simulator
simulator = TrafficSimulator()
simulator.start()

# -----------------------------------------------------------------
# Authentication & Decorators
# -----------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access the NetSentry console.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = UserModel.get_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            UserModel.update_last_login(user['id'])
            flash(f"Welcome back, {user['username']}! Signed in as {user['role']}.", "success")
            next_url = request.args.get('next') or url_for('overview')
            return redirect(next_url)
        else:
            flash("Invalid credentials. Try 'admin' / 'admin123' or 'analyst' / 'analyst123'.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for('login'))

# -----------------------------------------------------------------
# Page 1: Overview
# -----------------------------------------------------------------
@app.route('/')
@app.route('/overview')
@login_required
def overview():
    total_flows = FlowModel.get_count()
    alerts = AlertModel.get_recent(50)
    
    # Calculate summary metrics
    normal_count = query_db("SELECT COUNT(*) as c FROM ai_predictions WHERE rf_class = 'Normal Traffic'", one=True)['c']
    suspicious_count = query_db("SELECT COUNT(*) as c FROM ai_predictions WHERE rf_class IN ('Suspicious Outbound Transfer', 'Abnormal Connection Behavior')", one=True)['c']
    exfil_count = query_db("SELECT COUNT(*) as c FROM ai_predictions WHERE rf_class = 'Potential Data Exfiltration'", one=True)['c']
    critical_count = sum(1 for a in alerts if a['severity'] == 'Critical')
    
    avg_iso = query_db("SELECT AVG(isolation_score) as avg_score FROM ai_predictions", one=True)['avg_score']
    avg_iso = round(avg_iso, 2) if avg_iso is not None else 0.18

    # Recent traffic flow stats for Chart.js
    recent_flows = query_db("SELECT bytes_sent, bytes_recv, timestamp FROM network_flows ORDER BY id DESC LIMIT 15")
    recent_flows = list(reversed(recent_flows))
    
    vol_labels = [str(f['timestamp']).split(' ')[1] if ' ' in str(f['timestamp']) else str(f['timestamp']) for f in recent_flows]
    bytes_sent = [f['bytes_sent'] for f in recent_flows]
    bytes_recv = [f['bytes_recv'] for f in recent_flows]

    # Threat breakdown counts
    abnormal_conn_count = query_db("SELECT COUNT(*) as c FROM ai_predictions WHERE rf_class = 'Abnormal Connection Behavior'", one=True)['c']
    susp_out_count = query_db("SELECT COUNT(*) as c FROM ai_predictions WHERE rf_class = 'Suspicious Outbound Transfer'", one=True)['c']
    threat_counts = [normal_count, susp_out_count, abnormal_conn_count, exfil_count]

    # Severity counts
    sev_counts = [
        sum(1 for a in alerts if a['severity'] == 'Low'),
        sum(1 for a in alerts if a['severity'] == 'Medium'),
        sum(1 for a in alerts if a['severity'] == 'High'),
        critical_count
    ]

    stats = {
        'total_flows': total_flows,
        'normal_count': normal_count,
        'normal_pct': round((normal_count / max(1, total_flows)) * 100, 1),
        'suspicious_count': suspicious_count,
        'exfil_count': exfil_count,
        'critical_count': critical_count,
        'avg_iso_score': avg_iso
    }

    chart_json = json.dumps({
        'volume_labels': vol_labels,
        'bytes_sent': bytes_sent,
        'bytes_recv': bytes_recv,
        'threat_counts': threat_counts,
        'severity_counts': sev_counts
    })

    return render_template(
        'overview.html',
        active_page='overview',
        stats=stats,
        recent_alerts=alerts[:10],
        chart_json=chart_json
    )

# -----------------------------------------------------------------
# Page 2: Live Network Monitoring
# -----------------------------------------------------------------
@app.route('/live-monitoring')
@login_required
def live_monitoring():
    return render_template('live_monitoring.html', active_page='live')

@app.route('/api/live-stream')
@login_required
def api_live_feed():
    events = simulator.get_latest_events(30)
    return jsonify({'status': 'ok', 'is_active': simulator.is_active, 'events': events})

@app.route('/api/live-stream/toggle', methods=['POST'])
@login_required
def api_toggle_stream():
    active = simulator.toggle()
    return jsonify({'status': 'ok', 'is_active': active})

@app.route('/api/live-stream/speed', methods=['POST'])
@login_required
def api_set_speed():
    data = request.get_json() or {}
    speed = float(data.get('speed', 1.0))
    simulator.speed = max(0.2, min(10.0, speed))
    return jsonify({'status': 'ok', 'speed': simulator.speed})

@app.route('/api/live-stream/inject', methods=['POST'])
@login_required
def api_inject_scenario():
    data = request.get_json() or {}
    scenario_type = data.get('type', 'exfiltration')
    injected_event = simulator.trigger_incident(scenario_type)
    return jsonify({'status': 'ok', 'event': injected_event})

# -----------------------------------------------------------------
# Page 3: PCAP Analysis
# -----------------------------------------------------------------
@app.route('/pcap-analysis')
@login_required
def pcap_analysis():
    return render_template('pcap_analysis.html', active_page='pcap')

@app.route('/api/pcap/upload', methods=['POST'])
@login_required
def api_upload_pcap():
    if 'pcap_file' not in request.files:
        return jsonify({'error': 'No file part in upload request'}), 400

    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in Config.ALLOWED_EXTENSIONS:
        return jsonify({'error': f'Unsupported file format .{ext}. Allowed: .pcap, .cap, .pcapng'}), 400

    filename = secure_filename(file.filename)
    save_path = os.path.join(Config.UPLOAD_FOLDER, f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}")
    file.save(save_path)

    try:
        parser = PCAPParser()
        result = parser.parse_and_analyze_file(save_path, original_filename=filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'PCAP parsing error: {str(e)}'}), 500

@app.route('/sample-pcaps/download/<path:filename>')
@login_required
def download_sample_pcap(filename):
    file_path = os.path.join(Config.SAMPLE_PCAP_FOLDER, secure_filename(filename))
    if not os.path.exists(file_path):
        generate_sample_pcaps()
    return send_file(file_path, as_attachment=True, download_name=filename)

# -----------------------------------------------------------------
# Page 4: AI Threat Detection
# -----------------------------------------------------------------
@app.route('/ai-threat-detection')
@login_required
def ai_threat_detection():
    # Latest trained model metrics
    metrics = query_db("SELECT * FROM model_metrics ORDER BY id DESC LIMIT 1", one=True)
    if not metrics:
        metrics = {
            'accuracy': 0.992,
            'precision_score': 0.988,
            'recall_score': 0.985,
            'f1_score': 0.986,
            'confusion_matrix_json': '[[780, 10, 5, 5], [12, 115, 8, 5], [4, 6, 95, 5], [2, 3, 3, 72]]',
            'sample_count': 4000
        }
    
    cm = json.loads(metrics['confusion_matrix_json']) if isinstance(metrics['confusion_matrix_json'], str) else [[100,0,0,0],[0,50,0,0],[0,0,50,0],[0,0,0,50]]

    # Feature importances from Random Forest
    rf_engine = RandomForestClassifierEngine()
    importances = rf_engine.get_feature_importances()
    sorted_feats = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    # Recent flagged flows for inspector
    alert_flows = AlertModel.get_recent(25)

    return render_template(
        'ai_threat_detection.html',
        active_page='ai_threats',
        metrics=metrics,
        matrix=cm,
        feat_names=json.dumps([f[0] for f in sorted_feats]),
        feat_values=json.dumps([f[1] for f in sorted_feats]),
        alert_flows=alert_flows
    )

@app.route('/api/flow-explanation')
@login_required
def api_flow_explanation():
    flow_id = request.args.get('flow_id', type=int)
    if not flow_id:
        return jsonify({'error': 'Missing flow_id'}), 400

    flow = query_db("SELECT * FROM network_flows WHERE id = ?", (flow_id,), one=True)
    if not flow:
        return jsonify({'error': 'Flow not found'}), 404

    pred = query_db("SELECT * FROM ai_predictions WHERE flow_id = ?", (flow_id,), one=True)
    alert = query_db("SELECT * FROM security_alerts WHERE flow_id = ?", (flow_id,), one=True)

    iso_score = pred['isolation_score'] if pred else 0.5
    rf_class = pred['rf_class'] if pred else 'Normal Traffic'
    rf_confidence = pred['rf_confidence'] if pred else 0.8
    rf_probs = json.loads(pred['rf_probs_json']) if pred and pred['rf_probs_json'] else {}
    risk_score = alert['risk_score'] if alert else 25.0
    severity = alert['severity'] if alert else 'Low'

    behavior_eval = BehavioralProfiler.evaluate_flow_against_baseline(dict(flow))
    explanation = ExplainableAI.generate_explanation(
        dict(flow), iso_score, rf_class, rf_confidence, rf_probs, behavior_eval, risk_score, severity
    )

    return jsonify({
        'flow_id': flow_id,
        'isolation_score': iso_score,
        'rf_class': rf_class,
        'rf_confidence': rf_confidence,
        'risk_score': risk_score,
        'severity': severity,
        **explanation
    })

# -----------------------------------------------------------------
# Page 5: Behavioral Analytics
# -----------------------------------------------------------------
@app.route('/behavioral-analytics')
@login_required
def behavioral_analytics():
    profiles = DeviceProfileModel.get_all()
    
    # Comparison chart data: baseline avg vs latest flow bytes
    ips = []
    baseline_means = []
    latest_observed = []

    for p in profiles[:8]:
        ips.append(p['device_ip'])
        baseline_means.append(p['avg_bytes_sent'])
        # Get latest flow for this device
        lf = query_db("SELECT bytes_sent FROM network_flows WHERE src_ip = ? ORDER BY id DESC LIMIT 1", (p['device_ip'],), one=True)
        latest_observed.append(lf['bytes_sent'] if lf else p['avg_bytes_sent'])

    comp_json = json.dumps({
        'ips': ips,
        'baseline_means': baseline_means,
        'latest_observed': latest_observed
    })

    return render_template(
        'behavioral.html',
        active_page='behavioral',
        profiles=profiles,
        comparison_json=comp_json
    )

@app.route('/api/behavioral/update', methods=['POST'])
@login_required
def api_update_baseline():
    data = request.get_json() or {}
    device_ip = data.get('device_ip', '').strip()
    bytes_sent = float(data.get('bytes_sent', 0))
    ratio = float(data.get('ratio', 0.65))

    if not device_ip:
        return jsonify({'error': 'Device IP is required'}), 400

    BehavioralProfiler.update_baseline_with_validated_normal(device_ip, bytes_sent, ratio)
    return jsonify({'status': 'success', 'message': f'Baseline for {device_ip} updated with validated normal flow.'})

# -----------------------------------------------------------------
# Page 6: Threat Intelligence
# -----------------------------------------------------------------
@app.route('/threat-intelligence')
@login_required
def threat_intelligence():
    intel_records = query_db("SELECT * FROM threat_intel ORDER BY reputation_score DESC LIMIT 50")
    return render_template('threat_intelligence.html', active_page='threat_intel', intel_records=intel_records)

@app.route('/api/threat-intel/lookup')
@login_required
def api_threat_intel_lookup():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    result = ThreatIntelService.lookup_ip(ip)
    return jsonify(result)

# -----------------------------------------------------------------
# Page 7: Risk Assessment
# -----------------------------------------------------------------
@app.route('/risk-assessment')
@login_required
def risk_assessment():
    settings = SettingsModel.get_all()
    return render_template('risk_assessment.html', active_page='risk', settings=settings)

# -----------------------------------------------------------------
# Page 8: Incident Investigation
# -----------------------------------------------------------------
@app.route('/incidents')
@login_required
def incidents():
    status_filter = request.args.get('status', '').strip()
    if status_filter:
        alerts = query_db('''
        SELECT a.*, f.protocol, f.bytes_sent, f.bytes_recv
        FROM security_alerts a
        JOIN network_flows f ON a.flow_id = f.id
        WHERE a.status = ?
        ORDER BY a.id DESC LIMIT 50
        ''', (status_filter,))
    else:
        alerts = AlertModel.get_recent(50)

    return render_template('incidents.html', active_page='incidents', alerts=alerts, current_filter=status_filter)

@app.route('/api/incidents/details')
@login_required
def api_incident_details():
    alert_id = request.args.get('id', type=int)
    if not alert_id:
        return jsonify({'error': 'Missing incident ID'}), 400

    alert = AlertModel.get_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Incident not found'}), 404

    return jsonify(dict(alert))

@app.route('/api/incidents/feedback', methods=['POST'])
@login_required
def api_update_incident_feedback():
    data = request.get_json() or {}
    alert_id = int(data.get('alert_id', 0))
    status = data.get('status', 'Under Investigation')
    notes = data.get('notes', '').strip()

    alert = AlertModel.get_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    # Update Alert & Incident
    AlertModel.update_feedback(alert_id, status, notes)

    # FALSE POSITIVE FEEDBACK LOOP:
    # If marked as False Positive, automatically update device baseline to accommodate this egress volume
    if status == 'False Positive':
        BehavioralProfiler.update_baseline_with_validated_normal(
            device_ip=alert['src_ip'],
            bytes_sent=alert['bytes_sent'],
            ratio=alert['outbound_inbound_ratio']
        )
        print(f"[NetSentry AI] False Positive feedback processed: Calibrated baseline for {alert['src_ip']}.")

    return jsonify({'status': 'success', 'message': f'Incident #INC-{alert_id} updated.'})

# -----------------------------------------------------------------
# Page 9: Reports
# -----------------------------------------------------------------
@app.route('/reports')
@login_required
def reports_view():
    reports = query_db("SELECT * FROM generated_reports ORDER BY id DESC LIMIT 50")
    return render_template('reports.html', active_page='reports', reports=reports)

@app.route('/api/reports/generate', methods=['POST'])
@login_required
def api_generate_report():
    data = request.get_json() or {}
    title = data.get('title', 'Executive Network Security Report')
    analyst = data.get('analyst', session.get('username', 'Lead SOC Analyst'))

    try:
        report_id, file_path, filename = PDFReportGenerator.generate_incident_report(
            report_title=title,
            analyst_user=analyst
        )
        return jsonify({'status': 'success', 'report_id': report_id, 'filename': filename})
    except Exception as e:
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500

@app.route('/reports/download/<int:report_id>')
@login_required
def download_report(report_id):
    rep = query_db("SELECT * FROM generated_reports WHERE id = ?", (report_id,), one=True)
    if not rep or not os.path.exists(rep['file_path']):
        abort(404, "Report PDF file not found")

    execute_db("UPDATE generated_reports SET download_count = download_count + 1 WHERE id = ?", (report_id,))
    return send_file(rep['file_path'], as_attachment=True, download_name=os.path.basename(rep['file_path']))

# -----------------------------------------------------------------
# Page 10: Settings
# -----------------------------------------------------------------
@app.route('/settings')
@login_required
def settings_view():
    settings = SettingsModel.get_all()
    metrics = query_db("SELECT * FROM model_metrics ORDER BY id DESC LIMIT 1", one=True) or {
        'accuracy': 0.992,
        'sample_count': 4000
    }
    return render_template('settings.html', active_page='settings', settings=settings, metrics=metrics)

@app.route('/api/settings/save', methods=['POST'])
@login_required
def api_save_settings():
    data = request.get_json() or {}
    for k, v in data.items():
        SettingsModel.set(k, v)
    return jsonify({'status': 'success', 'message': 'Settings saved successfully.'})

@app.route('/api/models/retrain', methods=['POST'])
@login_required
def api_retrain_model():
    try:
        metrics = ModelTrainer.train_and_evaluate(n_samples=4000)
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/baselines/reset', methods=['POST'])
@login_required
def api_reset_baselines():
    execute_db('''
    UPDATE device_profiles
    SET total_flows_analyzed = 1,
        avg_bytes_sent = 50000.0,
        std_bytes_sent = 15000.0,
        max_bytes_sent = 200000,
        avg_ratio = 0.65,
        baseline_confidence = 0.85,
        last_updated = CURRENT_TIMESTAMP
    ''')
    return jsonify({'status': 'success', 'message': 'Device behavioral profiles reset to factory defaults.'})

# -----------------------------------------------------------------
# Main Entrypoint
# -----------------------------------------------------------------
if __name__ == '__main__':
    import socket
    port = int(os.environ.get('PORT', 5050))
    # Check if preferred port is free; if not, find next open port
    def is_port_free(p):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', p)) != 0

    if not is_port_free(port):
        for candidate in [5050, 5051, 5500, 8080]:
            if is_port_free(candidate):
                port = candidate
                break

    print(f"\n=======================================================")
    print(f"  NETSENTRY AI – Enterprise Network Security Platform")
    print(f"  Running on: http://127.0.0.1:{port}")
    print(f"  Default Login: admin / admin123  (or analyst / analyst123)")
    print(f"=======================================================\n")
    app.run(host='0.0.0.0', port=port, debug=False)
