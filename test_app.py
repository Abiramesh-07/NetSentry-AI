import os
import json
import unittest
from app import app
from database.db import get_db, query_db
from database.models import UserModel, FlowModel, DeviceProfileModel, AlertModel
from ai_engine.feature_extractor import FeatureExtractor
from ai_engine.isolation_forest import IsolationForestDetector
from ai_engine.random_forest import RandomForestClassifierEngine
from ai_engine.behavioral_profiler import BehavioralProfiler
from ai_engine.risk_engine import RiskEngine
from ai_engine.explainable_ai import ExplainableAI
from network.pcap_parser import PCAPParser
from threat_intel.intel_service import ThreatIntelService
from reports.pdf_generator import PDFReportGenerator

class NetSentryTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def test_01_feature_extractor(self):
        flow = {
            'bytes_sent': 500000,
            'bytes_recv': 10000,
            'packets_sent': 50,
            'packets_recv': 10,
            'duration': 2.5,
            'dst_port': 443,
            'protocol': 'TCP'
        }
        feats = FeatureExtractor.extract_from_flow(flow)
        self.assertEqual(len(feats), 13)
        self.assertGreater(feats[0], 0)
        print("Test 1: Feature Extractor OK")

    def test_02_isolation_forest(self):
        detector = IsolationForestDetector()
        flow = {'bytes_sent': 15000000, 'bytes_recv': 2000, 'outbound_inbound_ratio': 0.99, 'duration': 15.0}
        score, is_anom = detector.score_flow(flow)
        self.assertTrue(0.0 <= score <= 1.0)
        print(f"Test 2: Isolation Forest Score = {score} (Anomaly = {is_anom}) OK")

    def test_03_random_forest(self):
        rf = RandomForestClassifierEngine()
        flow = {'bytes_sent': 20000000, 'bytes_recv': 5000, 'outbound_inbound_ratio': 0.99, 'duration': 30.0, 'dst_port': 8443}
        pred_class, conf, probs = rf.predict_flow(flow)
        self.assertIn(pred_class, RandomForestClassifierEngine.CLASSES)
        self.assertTrue(0.0 <= conf <= 1.0)
        print(f"Test 3: Random Forest Predicted: {pred_class} (Conf: {conf}) OK")

    def test_04_behavioral_profiler(self):
        flow = {'src_ip': '192.168.1.105', 'bytes_sent': 850000, 'outbound_inbound_ratio': 0.92, 'duration': 4.0}
        eval_res = BehavioralProfiler.evaluate_flow_against_baseline(flow)
        self.assertIn('volume_multiplier', eval_res)
        self.assertIn('behavior_deviation_score', eval_res)
        print(f"Test 4: Behavioral Profiler Multiplier: {eval_res['volume_multiplier']}x, Dev: {eval_res['behavior_deviation_score']} OK")

    def test_05_risk_engine(self):
        flow = {'bytes_sent': 12000000}
        beh = {'volume_multiplier': 6.0, 'behavior_deviation_score': 0.75}
        score, severity, factors = RiskEngine.calculate_risk(
            iso_score=0.82,
            rf_class='Potential Data Exfiltration',
            rf_confidence=0.94,
            behavior_eval=beh,
            threat_intel_score=90,
            flow_dict=flow
        )
        self.assertGreaterEqual(score, 70.0)
        self.assertIn(severity, ['High', 'Critical'])
        print(f"Test 5: Dynamic Risk Score: {score}/100 ({severity}) OK")

    def test_06_explainable_ai(self):
        flow = {'src_ip': '192.168.1.142', 'dst_ip': '198.51.100.77', 'dst_port': 8443, 'bytes_sent': 14000000, 'bytes_recv': 8000, 'outbound_inbound_ratio': 0.98, 'duration': 22.0}
        beh = {'volume_multiplier': 8.5, 'baseline_avg_bytes': 50000, 'is_off_hours': True}
        xai = ExplainableAI.generate_explanation(flow, 0.85, 'Potential Data Exfiltration', 0.95, {}, beh, 91.0, 'Critical')
        self.assertIn('primary_reason', xai)
        self.assertGreater(len(xai['feature_contributions']), 0)
        self.assertGreater(len(xai['recommended_actions']), 0)
        print("Test 6: Explainable AI Attribution OK")

    def test_07_threat_intel(self):
        intel = ThreatIntelService.lookup_ip('198.51.100.77')
        self.assertEqual(intel['ip_address'], '198.51.100.77')
        self.assertGreater(intel['reputation_score'], 50)
        print("Test 7: Threat Intel Feed Lookup OK")

    def test_08_pdf_generator(self):
        r_id, r_path, r_name = PDFReportGenerator.generate_incident_report(report_title="Test NetSentry Report")
        self.assertTrue(os.path.exists(r_path))
        self.assertGreater(os.path.getsize(r_path), 1000)
        print(f"Test 8: ReportLab PDF Report Generated: {r_name} OK")

    def test_09_flask_routes(self):
        # 1. Login
        login_res = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b'NetSentry', login_res.data)

        # 2. Overview
        ov_res = self.client.get('/overview')
        self.assertEqual(ov_res.status_code, 200)

        # 3. Live Monitoring
        lm_res = self.client.get('/live-monitoring')
        self.assertEqual(lm_res.status_code, 200)

        # 4. Live Feed API
        feed_res = self.client.get('/api/live-stream')
        self.assertEqual(feed_res.status_code, 200)

        # 5. PCAP Analysis page
        pcap_res = self.client.get('/pcap-analysis')
        self.assertEqual(pcap_res.status_code, 200)

        # 6. AI Threat Detection
        ai_res = self.client.get('/ai-threat-detection')
        self.assertEqual(ai_res.status_code, 200)

        # 7. Behavioral Analytics
        beh_res = self.client.get('/behavioral-analytics')
        self.assertEqual(beh_res.status_code, 200)

        # 8. Threat Intelligence
        ti_res = self.client.get('/threat-intelligence')
        self.assertEqual(ti_res.status_code, 200)

        # 9. Risk Assessment
        risk_res = self.client.get('/risk-assessment')
        self.assertEqual(risk_res.status_code, 200)

        # 10. Incidents
        inc_res = self.client.get('/incidents')
        self.assertEqual(inc_res.status_code, 200)

        # 11. Reports
        rep_res = self.client.get('/reports')
        self.assertEqual(rep_res.status_code, 200)

        # 12. Settings
        set_res = self.client.get('/settings')
        self.assertEqual(set_res.status_code, 200)

        print("Test 9: All 10 Flask routes & APIs return HTTP 200 OK")

if __name__ == '__main__':
    unittest.main()
