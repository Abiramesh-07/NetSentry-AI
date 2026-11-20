import time
import random
import threading
from datetime import datetime
from collections import deque

from ai_engine.isolation_forest import IsolationForestDetector
from ai_engine.random_forest import RandomForestClassifierEngine
from ai_engine.behavioral_profiler import BehavioralProfiler
from ai_engine.risk_engine import RiskEngine
from ai_engine.explainable_ai import ExplainableAI
from database.models import FlowModel, PredictionModel, AlertModel, ThreatIntelModel, SettingsModel
from threat_intel.intel_service import ThreatIntelService

class TrafficSimulator:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(TrafficSimulator, cls).__new__(cls)
                cls._instance._init_simulator()
            return cls._instance

    def _init_simulator(self):
        self.is_active = True
        self.worker_thread = None
        self.live_buffer = deque(maxlen=100)
        self.speed = 1.0
        self.iso_detector = IsolationForestDetector()
        self.rf_engine = RandomForestClassifierEngine()
        
        # Enterprise internal endpoints pool
        self.internal_ips = [
            ("192.168.1.102", "WS-ENG-ALICE"),
            ("192.168.1.105", "WS-FIN-BOB"),
            ("192.168.1.114", "WS-MKT-CAROL"),
            ("192.168.1.142", "DEV-SERVER-01"),
            ("192.168.1.189", "LAB-TEST-NODE"),
            ("192.168.1.200", "GATEWAY-PROXY")
        ]

        # External destinations
        self.external_destinations = [
            ("140.82.36.4", 443, "HTTPS", "github.com"),
            ("172.217.16.206", 443, "HTTPS", "google.com"),
            ("52.96.166.130", 443, "HTTPS", "outlook.office365.com"),
            ("8.8.8.8", 53, "DNS", "Google Public DNS"),
            ("1.1.1.1", 53, "DNS", "Cloudflare DNS"),
            ("185.199.108.153", 443, "HTTPS", "cdn.jsdelivr.net"),
            ("198.51.100.77", 8443, "HTTPS-Alt", "Unindexed Offshore IP"),
            ("203.0.113.88", 4444, "Metasploit/C2", "Rogue Dynamic Host")
        ]

    def start(self):
        if self.worker_thread is None or not self.worker_thread.is_alive():
            self.is_active = True
            self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
            self.worker_thread.start()
            print("[NetSentry AI] Real-time traffic simulation thread started.")

    def pause(self):
        self.is_active = False

    def resume(self):
        self.is_active = True

    def toggle(self):
        self.is_active = not self.is_active
        return self.is_active

    def trigger_incident(self, incident_type="exfiltration"):
        """Forces an immediate simulated incident flow for live demonstration."""
        if incident_type == "exfiltration":
            src_ip, hostname = random.choice(self.internal_ips[:3])
            dst_ip = "198.51.100.77" # Suspicious offshore destination
            dst_port = 8443
            bytes_sent = random.randint(8500000, 24000000) # 8.5MB to 24MB exfil
            bytes_recv = random.randint(4000, 15000)
            duration = round(random.uniform(12.0, 45.0), 2)
            service = "HTTPS-Alt"
            proto = "TCP"
        elif incident_type == "dns_tunnel":
            src_ip, hostname = self.internal_ips[4]
            dst_ip = "203.0.113.88"
            dst_port = 53
            bytes_sent = random.randint(45000, 120000) # Large TXT volume
            bytes_recv = random.randint(2000, 5000)
            duration = round(random.uniform(4.0, 15.0), 2)
            service = "DNS"
            proto = "UDP"
        else: # c2_beacon
            src_ip, hostname = self.internal_ips[3]
            dst_ip = "203.0.113.88"
            dst_port = 4444
            bytes_sent = random.randint(64, 128)
            bytes_recv = random.randint(32, 64)
            duration = 0.05
            service = "Metasploit/C2"
            proto = "TCP"

        flow_data = self._process_and_store_flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(49152, 65535),
            dst_port=dst_port,
            protocol=proto,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            duration=duration,
            service=service,
            is_simulated=1
        )
        return flow_data

    def _process_and_store_flow(self, src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent, bytes_recv, duration, service, is_simulated=1):
        total_bytes = bytes_sent + bytes_recv
        ratio = bytes_sent / (total_bytes + 1.0)
        packets_sent = max(1, int(bytes_sent / random.randint(400, 1460)))
        packets_recv = max(1, int(bytes_recv / random.randint(400, 1460)))

        flow_dict = {
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'total_bytes': total_bytes,
            'packets_sent': packets_sent,
            'packets_recv': packets_recv,
            'duration': duration,
            'outbound_inbound_ratio': round(ratio, 3),
            'flags': 'PA,A',
            'service': service,
            'is_simulated': is_simulated,
            'pcap_filename': None
        }

        # Store in DB
        flow_id = FlowModel.insert(flow_dict)
        flow_dict['id'] = flow_id

        # 1. Isolation Forest Anomaly Score
        iso_score, is_iso_anomaly = self.iso_detector.score_flow(flow_dict)

        # 2. Random Forest Classification
        rf_class, rf_confidence, rf_probs = self.rf_engine.predict_flow(flow_dict)

        # 3. Behavioral Baseline Evaluation
        behavior_eval = BehavioralProfiler.evaluate_flow_against_baseline(flow_dict)

        # 4. Threat Intelligence Reputation
        ti_lookup = ThreatIntelService.lookup_ip(dst_ip)
        ti_score = ti_lookup.get('reputation_score', 0)

        # 5. Dynamic Risk Scoring
        risk_score, severity, risk_factors = RiskEngine.calculate_risk(
            iso_score, rf_class, rf_confidence, behavior_eval, ti_score, flow_dict
        )

        # 6. Explainable AI Feature Attribution & SOC Guidance
        explanation = ExplainableAI.generate_explanation(
            flow_dict, iso_score, rf_class, rf_confidence, rf_probs, behavior_eval, risk_score, severity
        )

        # Record Prediction in DB
        PredictionModel.record(
            flow_id, iso_score, is_iso_anomaly, rf_class, rf_confidence,
            rf_probs, explanation['feature_contributions']
        )

        # Generate Alert if anomalous
        alert_id = None
        if risk_score >= 40.0 or rf_class != 'Normal Traffic' or is_iso_anomaly:
            alert_type = "Potential Data Exfiltration" if rf_class == 'Potential Data Exfiltration' else ("Suspicious Outbound Transfer" if rf_class == 'Suspicious Outbound Transfer' else "Abnormal Network Flow")
            alert_id = AlertModel.create(
                flow_id=flow_id,
                alert_type=alert_type,
                severity=severity,
                risk_score=risk_score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                summary=explanation['primary_reason']
            )

        live_item = {
            'id': flow_id,
            'timestamp': flow_dict['timestamp'],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'total_bytes': total_bytes,
            'duration': duration,
            'outbound_inbound_ratio': round(ratio, 3),
            'service': service,
            'isolation_score': iso_score,
            'rf_class': rf_class,
            'rf_confidence': rf_confidence,
            'risk_score': risk_score,
            'severity': severity,
            'alert_id': alert_id,
            'primary_reason': explanation['primary_reason']
        }

        self.live_buffer.appendleft(live_item)
        return live_item

    def _run_loop(self):
        while True:
            if not self.is_active:
                time.sleep(1.0)
                continue

            try:
                # 90% normal traffic, 10% occasional anomalous event for organic demonstration
                roll = random.random()
                if roll > 0.94:
                    # Rare organic anomalous event
                    self.trigger_incident("exfiltration" if random.random() > 0.5 else "c2_beacon")
                else:
                    # Normal organic background flow
                    src_ip, hostname = random.choice(self.internal_ips)
                    dst_ip, dst_port, service, domain = random.choice(self.external_destinations[:6]) # Clean destinations
                    
                    if service == "DNS":
                        bytes_sent = random.randint(50, 160)
                        bytes_recv = random.randint(80, 450)
                        dur = round(random.uniform(0.01, 0.08), 3)
                        proto = "UDP"
                    else: # HTTPS/Web
                        bytes_sent = random.randint(600, 4500)
                        bytes_recv = random.randint(4000, 85000) # Normal inbound dominance
                        dur = round(random.uniform(0.2, 4.0), 2)
                        proto = "TCP"

                    self._process_and_store_flow(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=random.randint(49152, 65535),
                        dst_port=dst_port,
                        protocol=proto,
                        bytes_sent=bytes_sent,
                        bytes_recv=bytes_recv,
                        duration=dur,
                        service=service,
                        is_simulated=1
                    )
            except Exception as e:
                print(f"[NetSentry AI Simulator Error]: {e}")

            time.sleep(max(0.5, 2.5 / self.speed))

    def get_latest_events(self, limit=20):
        return list(self.live_buffer)[:limit]
