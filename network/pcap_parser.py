import os
from datetime import datetime
from collections import defaultdict
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ai_engine.feature_extractor import FeatureExtractor
from ai_engine.isolation_forest import IsolationForestDetector
from ai_engine.random_forest import RandomForestClassifierEngine
from ai_engine.behavioral_profiler import BehavioralProfiler
from ai_engine.risk_engine import RiskEngine
from ai_engine.explainable_ai import ExplainableAI
from database.models import FlowModel, PredictionModel, AlertModel, ThreatIntelModel
from threat_intel.intel_service import ThreatIntelService

class PCAPParser:
    PORT_TO_SERVICE = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        3389: 'RDP', 4444: 'Metasploit/C2', 6667: 'IRC', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 9001: 'Tor-Port'
    }

    def __init__(self):
        self.iso_detector = IsolationForestDetector()
        self.rf_engine = RandomForestClassifierEngine()

    def parse_and_analyze_file(self, file_path, original_filename="uploaded.pcap"):
        """
        Parses a PCAP file, reconstructs flows, feeds each through NetSentry AI,
        and saves results in the SQLite database.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        print(f"[NetSentry AI] Reading PCAP: {file_path}...")
        try:
            packets = rdpcap(file_path)
        except Exception as e:
            raise ValueError(f"Failed to parse PCAP file: {str(e)}")

        packet_count = len(packets)
        if packet_count == 0:
            return {"status": "empty", "message": "PCAP contains no packets", "flows_analyzed": 0}

        # 1. Flow Reconstruction by Bidirectional 5-Tuple
        # key: (min(src, dst), max(src, dst), min(sport, dport), max(sport, dport), proto)
        raw_flows = defaultdict(lambda: {
            'initiator': None,
            'responder': None,
            'sport': 0,
            'dport': 0,
            'protocol': 'TCP',
            'pkts_sent': 0,
            'pkts_recv': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
            'start_time': None,
            'end_time': None,
            'flags': set()
        })

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            pkt_len = len(pkt)
            pkt_time = float(pkt.time)

            if pkt.haslayer(TCP):
                proto = 'TCP'
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
            elif pkt.haslayer(UDP):
                proto = 'UDP'
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                flags = ''
            elif pkt.haslayer(ICMP):
                proto = 'ICMP'
                sport = 0
                dport = 0
                flags = ''
            else:
                proto = 'OTHER'
                sport = 0
                dport = 0
                flags = ''

            # Canonical key
            if (src_ip, sport) <= (dst_ip, dport):
                flow_key = (src_ip, dst_ip, sport, dport, proto)
                is_initiator = True
            else:
                flow_key = (dst_ip, src_ip, dport, sport, proto)
                is_initiator = False

            f = raw_flows[flow_key]
            if f['initiator'] is None:
                f['initiator'] = src_ip
                f['responder'] = dst_ip
                f['sport'] = sport
                f['dport'] = dport
                f['protocol'] = proto
                f['start_time'] = pkt_time
                f['end_time'] = pkt_time
            else:
                f['start_time'] = min(f['start_time'], pkt_time)
                f['end_time'] = max(f['end_time'], pkt_time)

            if src_ip == f['initiator']:
                f['bytes_sent'] += pkt_len
                f['pkts_sent'] += 1
            else:
                f['bytes_recv'] += pkt_len
                f['pkts_recv'] += 1

            if flags:
                f['flags'].add(str(flags))

        # 2. Analyze each reconstructed flow with the AI Engine
        results = []
        alerts_generated = 0
        normal_count = 0
        suspicious_count = 0
        exfil_count = 0

        for key, f in raw_flows.items():
            duration = max(0.001, f['end_time'] - f['start_time']) if f['end_time'] and f['start_time'] else 0.1
            total_bytes = f['bytes_sent'] + f['bytes_recv']
            ratio = f['bytes_sent'] / (total_bytes + 1.0)
            service = self.PORT_TO_SERVICE.get(f['dport'], self.PORT_TO_SERVICE.get(f['sport'], 'General'))

            # Convert to flow dict
            flow_dict = {
                'timestamp': datetime.utcfromtimestamp(f['start_time']).strftime('%Y-%m-%d %H:%M:%S') if f['start_time'] else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': f['initiator'],
                'dst_ip': f['responder'],
                'src_port': f['sport'],
                'dst_port': f['dport'],
                'protocol': f['protocol'],
                'bytes_sent': f['bytes_sent'],
                'bytes_recv': f['bytes_recv'],
                'total_bytes': total_bytes,
                'packets_sent': max(1, f['pkts_sent']),
                'packets_recv': max(1, f['pkts_recv']),
                'duration': round(duration, 3),
                'outbound_inbound_ratio': round(ratio, 3),
                'flags': ','.join(sorted(f['flags'])),
                'service': service,
                'is_simulated': 0,
                'pcap_filename': original_filename
            }

            # Insert flow into DB
            flow_id = FlowModel.insert(flow_dict)
            flow_dict['id'] = flow_id

            # AI Inference Pipeline:
            # 1. Isolation Forest Anomaly Score
            iso_score, is_iso_anomaly = self.iso_detector.score_flow(flow_dict)

            # 2. Random Forest Classification
            rf_class, rf_confidence, rf_probs = self.rf_engine.predict_flow(flow_dict)

            # 3. Behavioral Profile Evaluation
            behavior_eval = BehavioralProfiler.evaluate_flow_against_baseline(flow_dict)

            # 4. Threat Intel Reputation Check
            ti_lookup = ThreatIntelService.lookup_ip(flow_dict['dst_ip'])
            ti_score = ti_lookup.get('reputation_score', 0)

            # 5. Dynamic Risk Scoring
            risk_score, severity, risk_factors = RiskEngine.calculate_risk(
                iso_score, rf_class, rf_confidence, behavior_eval, ti_score, flow_dict
            )

            # 6. Explainable AI Feature Attribution & SOC Guidance
            explanation = ExplainableAI.generate_explanation(
                flow_dict, iso_score, rf_class, rf_confidence, rf_probs, behavior_eval, risk_score, severity
            )

            # Record Prediction
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
                    src_ip=flow_dict['src_ip'],
                    dst_ip=flow_dict['dst_ip'],
                    summary=explanation['primary_reason']
                )
                alerts_generated += 1

            if rf_class == 'Potential Data Exfiltration':
                exfil_count += 1
            elif rf_class in ('Suspicious Outbound Transfer', 'Abnormal Connection Behavior'):
                suspicious_count += 1
            else:
                normal_count += 1

            results.append({
                'flow_id': flow_id,
                'src_ip': flow_dict['src_ip'],
                'dst_ip': flow_dict['dst_ip'],
                'protocol': flow_dict['protocol'],
                'bytes_sent': flow_dict['bytes_sent'],
                'bytes_recv': flow_dict['bytes_recv'],
                'ratio': flow_dict['outbound_inbound_ratio'],
                'duration': flow_dict['duration'],
                'isolation_score': iso_score,
                'rf_class': rf_class,
                'rf_confidence': rf_confidence,
                'risk_score': risk_score,
                'severity': severity,
                'alert_id': alert_id,
                'primary_reason': explanation['primary_reason']
            })

        return {
            'status': 'success',
            'filename': original_filename,
            'packets_parsed': packet_count,
            'flows_analyzed': len(results),
            'normal_count': normal_count,
            'suspicious_count': suspicious_count,
            'exfiltration_alerts': exfil_count,
            'total_alerts_generated': alerts_generated,
            'flows': results[:30] # Top 30 flows for immediate inspection
        }
