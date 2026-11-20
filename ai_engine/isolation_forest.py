import os
import joblib
import warnings
import numpy as np
import ai_engine.sklearn_patch
from sklearn.ensemble import IsolationForest
from config import Config
from ai_engine.feature_extractor import FeatureExtractor

warnings.filterwarnings('ignore')

class IsolationForestDetector:
    MODEL_PATH = os.path.join(Config.MODEL_DIR, 'isolation_forest.joblib')

    def __init__(self, contamination=0.12, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.is_trained = False
        self._load_or_init()

    def _load_or_init(self):
        os.makedirs(Config.MODEL_DIR, exist_ok=True)
        if os.path.exists(self.MODEL_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
                self.model.n_jobs = 1
                self.is_trained = True
            except Exception as e:
                print(f"[NetSentry AI] Could not load Isolation Forest model: {e}")
                self._init_new_model()
        else:
            self._init_new_model()

    def _init_new_model(self):
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1
        )
        self.is_trained = False

    def fit(self, X):
        """Fit Isolation Forest on feature matrix X (N x 13)."""
        self.model.fit(X)
        self.is_trained = True
        joblib.dump(self.model, self.MODEL_PATH)
        return self

    def score_flow(self, flow_dict):
        """
        Calculates normalized anomaly score in [0.0, 1.0] and boolean anomaly flag.
        Higher score = more anomalous.
        """
        feats = FeatureExtractor.extract_from_flow(flow_dict).reshape(1, -1)
        if not self.is_trained:
            # Fallback heuristic if model not trained yet
            ratio = flow_dict.get('outbound_inbound_ratio', 0.5)
            bytes_sent = flow_dict.get('bytes_sent', 1000)
            score = 0.2 + (0.5 if ratio > 0.85 else 0.0) + (0.3 if bytes_sent > 500000 else 0.0)
            score = min(0.99, max(0.01, score))
            return round(score, 4), score >= Config.ISOLATION_ANOMALY_THRESHOLD

        # sklearn Isolation Forest raw score: lower means more anomalous (e.g. -0.8 to -0.3)
        raw_score = self.model.score_samples(feats)[0]
        # Normalize raw score (-0.8 to -0.3 range) to [0, 1] scale where 1 is highest anomaly
        norm_score = 1.0 / (1.0 + np.exp( (raw_score + 0.50) * 12.0 ))
        norm_score = float(np.clip(norm_score, 0.01, 0.99))
        
        is_anomaly = norm_score >= Config.ISOLATION_ANOMALY_THRESHOLD
        return round(norm_score, 4), is_anomaly
