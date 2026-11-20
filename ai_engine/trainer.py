import os
import json
import numpy as np
import pandas as pd
import ai_engine.sklearn_patch
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from ai_engine.feature_extractor import FeatureExtractor
from ai_engine.isolation_forest import IsolationForestDetector
from ai_engine.random_forest import RandomForestClassifierEngine
from database.db import get_db, execute_db

class ModelTrainer:
    """
    Trains and validates Isolation Forest and Random Forest models
    using realistic network flow distributions modeled after CIC-IDS2017/2018.
    Computes real metrics: Accuracy, Precision, Recall, F1, and Confusion Matrix.
    """

    @staticmethod
    def generate_cic_realistic_dataset(n_samples=5000, random_seed=42):
        np.random.seed(random_seed)

        data = []
        labels = []

        # Class distribution:
        # 0: Normal Traffic (70%)
        # 1: Suspicious Outbound Transfer (12%)
        # 2: Abnormal Connection Behavior (10%)
        # 3: Potential Data Exfiltration (8%)

        n_normal = int(n_samples * 0.70)
        n_susp_out = int(n_samples * 0.12)
        n_abnormal_conn = int(n_samples * 0.10)
        n_exfil = n_samples - (n_normal + n_susp_out + n_abnormal_conn)

        # 1. Normal Traffic: Interactive browsing, API calls, streaming, DNS lookups
        for _ in range(n_normal):
            flow_type = np.random.choice(['web_browse', 'dns_query', 'download', 'api_call'])
            if flow_type == 'web_browse':
                bytes_sent = np.random.lognormal(mean=7.5, sigma=0.6)    # ~1,800 bytes
                bytes_recv = np.random.lognormal(mean=10.5, sigma=1.0)   # ~36,000 bytes (inbound heavy)
                dst_port = np.random.choice([80, 443])
                proto = 6
                dur = np.random.uniform(0.2, 5.0)
                pkts_sent = max(3, int(bytes_sent / 600))
                pkts_recv = max(5, int(bytes_recv / 1400))
            elif flow_type == 'dns_query':
                bytes_sent = np.random.uniform(40, 150)
                bytes_recv = np.random.uniform(80, 500)
                dst_port = 53
                proto = 17
                dur = np.random.uniform(0.01, 0.1)
                pkts_sent = 1
                pkts_recv = 1
            elif flow_type == 'download':
                bytes_sent = np.random.uniform(500, 5000)
                bytes_recv = np.random.lognormal(mean=13.0, sigma=0.8)   # ~440 KB
                dst_port = 443
                proto = 6
                dur = np.random.uniform(1.0, 15.0)
                pkts_sent = max(5, int(bytes_sent / 500))
                pkts_recv = max(20, int(bytes_recv / 1460))
            else: # api_call
                bytes_sent = np.random.uniform(800, 3000)
                bytes_recv = np.random.uniform(1000, 8000)
                dst_port = 443
                proto = 6
                dur = np.random.uniform(0.05, 0.8)
                pkts_sent = np.random.randint(2, 6)
                pkts_recv = np.random.randint(2, 8)

            hour = np.random.choice(range(8, 19)) # Business hours
            flow = {
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': pkts_sent,
                'packets_recv': pkts_recv,
                'duration': dur,
                'dst_port': dst_port,
                'protocol': 'TCP' if proto == 6 else 'UDP',
                'timestamp': f"2026-11-13 {hour:02d}:30:00"
            }
            data.append(FeatureExtractor.extract_from_flow(flow))
            labels.append(0)

        # 2. Suspicious Outbound Transfer: Above-normal outbound volumes, irregular uploads
        for _ in range(n_susp_out):
            bytes_sent = np.random.lognormal(mean=13.5, sigma=0.7)  # ~720 KB
            bytes_recv = np.random.uniform(1000, 25000)
            dst_port = np.random.choice([80, 443, 8080, 8443])
            dur = np.random.uniform(2.0, 20.0)
            pkts_sent = max(20, int(bytes_sent / 1200))
            pkts_recv = max(5, int(bytes_recv / 500))
            hour = np.random.choice(range(0, 24))

            flow = {
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': pkts_sent,
                'packets_recv': pkts_recv,
                'duration': dur,
                'dst_port': dst_port,
                'protocol': 'TCP',
                'timestamp': f"2026-11-13 {hour:02d}:15:00"
            }
            data.append(FeatureExtractor.extract_from_flow(flow))
            labels.append(1)

        # 3. Abnormal Connection Behavior: Port scanning, fast SYN bursts, tiny heartbeat beacons
        for _ in range(n_abnormal_conn):
            variant = np.random.choice(['beacon', 'port_probe', 'failed_egress'])
            if variant == 'beacon':
                bytes_sent = np.random.uniform(64, 128)
                bytes_recv = np.random.uniform(32, 64)
                dur = np.random.uniform(0.01, 0.05)
                dst_port = np.random.choice([4444, 6667, 9001, 53])
                pkts_sent = 1
                pkts_recv = 1
            else:
                bytes_sent = np.random.uniform(40, 200)
                bytes_recv = 0
                dur = np.random.uniform(0.001, 0.02)
                dst_port = np.random.randint(1024, 65535)
                pkts_sent = 2
                pkts_recv = 0

            hour = np.random.choice([1, 2, 3, 4, 22, 23]) # Late off-hours
            flow = {
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': pkts_sent,
                'packets_recv': pkts_recv,
                'duration': dur,
                'dst_port': dst_port,
                'protocol': 'TCP',
                'timestamp': f"2026-11-13 {hour:02d}:45:00"
            }
            data.append(FeatureExtractor.extract_from_flow(flow))
            labels.append(2)

        # 4. Potential Data Exfiltration: Massive outbound payload, asymmetric ratio (>95%), DNS tunneling
        for _ in range(n_exfil):
            exfil_type = np.random.choice(['bulk_https', 'dns_tunnel', 'archive_dump'])
            if exfil_type == 'bulk_https':
                bytes_sent = np.random.lognormal(mean=16.0, sigma=0.8) # ~8.8 MB
                bytes_recv = np.random.uniform(2000, 30000)
                dst_port = 443
                dur = np.random.uniform(5.0, 45.0)
                pkts_sent = max(100, int(bytes_sent / 1460))
                pkts_recv = max(10, int(bytes_recv / 600))
            elif exfil_type == 'dns_tunnel':
                bytes_sent = np.random.uniform(15000, 80000)
                bytes_recv = np.random.uniform(1000, 4000)
                dst_port = 53
                dur = np.random.uniform(1.0, 10.0)
                pkts_sent = max(50, int(bytes_sent / 250))
                pkts_recv = max(20, int(bytes_recv / 100))
            else: # archive_dump
                bytes_sent = np.random.lognormal(mean=17.0, sigma=0.6) # ~24 MB
                bytes_recv = np.random.uniform(5000, 20000)
                dst_port = np.random.choice([8080, 8443, 22, 9001])
                dur = np.random.uniform(10.0, 60.0)
                pkts_sent = max(200, int(bytes_sent / 1460))
                pkts_recv = max(15, int(bytes_recv / 500))

            hour = np.random.choice([0, 1, 2, 3, 4, 5, 23]) # Dead of night
            flow = {
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': pkts_sent,
                'packets_recv': pkts_recv,
                'duration': dur,
                'dst_port': dst_port,
                'protocol': 'UDP' if exfil_type == 'dns_tunnel' else 'TCP',
                'timestamp': f"2026-11-13 {hour:02d}:10:00"
            }
            data.append(FeatureExtractor.extract_from_flow(flow))
            labels.append(3)

        X = np.array(data)
        y = np.array(labels)

        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=0.0)
        perm = np.random.permutation(len(X))
        return X[perm], y[perm]

    @staticmethod
    def train_and_evaluate(n_samples=4000):
        print("[NetSentry AI] Generating realistic CIC-IDS2017/2018 distribution flow dataset...")
        X, y = ModelTrainer.generate_cic_realistic_dataset(n_samples=n_samples)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        print(f"[NetSentry AI] Training dataset split: {len(X_train)} train, {len(X_test)} test samples.")

        print("[NetSentry AI] Fitting Isolation Forest for unsupervised anomaly detection...")
        iso_detector = IsolationForestDetector()
        iso_detector.fit(X_train)

        print("[NetSentry AI] Fitting Random Forest Multi-class Classifier...")
        rf_engine = RandomForestClassifierEngine()
        rf_engine.fit(X_train, y_train)

        y_pred = rf_engine.model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()

        metrics = {
            'accuracy': round(float(acc), 4),
            'precision': round(float(prec), 4),
            'recall': round(float(rec), 4),
            'f1_score': round(float(f1), 4),
            'confusion_matrix': cm,
            'classes': RandomForestClassifierEngine.CLASSES,
            'sample_count': len(X)
        }

        print(f"[NetSentry AI] Model Evaluation Results:")
        print(f"  - Accuracy:  {metrics['accuracy']*100:.2f}%")
        print(f"  - Precision: {metrics['precision']*100:.2f}%")
        print(f"  - Recall:    {metrics['recall']*100:.2f}%")
        print(f"  - F1-Score:  {metrics['f1_score']*100:.2f}%")

        execute_db('''
        INSERT INTO model_metrics (
            model_name, version, accuracy, precision_score, recall_score,
            f1_score, confusion_matrix_json, sample_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'NetSentry Hybrid RF-IForest',
            'v1.0-cicids',
            metrics['accuracy'],
            metrics['precision'],
            metrics['recall'],
            metrics['f1_score'],
            json.dumps(cm),
            metrics['sample_count']
        ))

        return metrics

if __name__ == '__main__':
    ModelTrainer.train_and_evaluate(n_samples=4000)
