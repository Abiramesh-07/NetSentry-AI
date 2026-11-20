import os
import joblib
import warnings
import numpy as np
import ai_engine.sklearn_patch
from sklearn.ensemble import RandomForestClassifier
from config import Config
from ai_engine.feature_extractor import FeatureExtractor

warnings.filterwarnings('ignore')

class RandomForestClassifierEngine:
    MODEL_PATH = os.path.join(Config.MODEL_DIR, 'random_forest.joblib')
    
    CLASSES = [
        'Normal Traffic',
        'Suspicious Outbound Transfer',
        'Abnormal Connection Behavior',
        'Potential Data Exfiltration'
    ]

    def __init__(self, random_state=42):
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
                print(f"[NetSentry AI] Could not load Random Forest model: {e}")
                self._init_new_model()
        else:
            self._init_new_model()

    def _init_new_model(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            random_state=self.random_state,
            class_weight='balanced',
            n_jobs=1
        )
        self.is_trained = False

    def fit(self, X, y):
        """Fit Random Forest on feature matrix X and multiclass targets y."""
        self.model.fit(X, y)
        self.is_trained = True
        joblib.dump(self.model, self.MODEL_PATH)
        return self

    def predict_flow(self, flow_dict):
        """
        Predicts class label, confidence score, and full probability distribution.
        """
        feats = FeatureExtractor.extract_from_flow(flow_dict).reshape(1, -1)
        if not self.is_trained:
            # Fallback heuristic
            ratio = flow_dict.get('outbound_inbound_ratio', 0.5)
            bytes_sent = flow_dict.get('bytes_sent', 1000)
            if ratio > 0.85 and bytes_sent > 1000000:
                cls = 'Potential Data Exfiltration'
                conf = 0.88
            elif ratio > 0.75:
                cls = 'Suspicious Outbound Transfer'
                conf = 0.72
            elif flow_dict.get('duration', 1.0) < 0.05 and flow_dict.get('packets_sent', 1) > 20:
                cls = 'Abnormal Connection Behavior'
                conf = 0.70
            else:
                cls = 'Normal Traffic'
                conf = 0.94

            probs = {c: (conf if c == cls else round((1.0 - conf)/3.0, 3)) for c in self.CLASSES}
            return cls, conf, probs

        pred_idx = self.model.predict(feats)[0]
        probs = self.model.predict_proba(feats)[0]
        predicted_class = self.CLASSES[pred_idx]
        confidence = float(probs[pred_idx])
        
        prob_dict = {
            self.CLASSES[i]: round(float(probs[i]), 4)
            for i in range(len(self.CLASSES))
        }

        return predicted_class, round(confidence, 4), prob_dict

    def get_feature_importances(self):
        """Returns relative importance of each feature in the trained forest."""
        if not self.is_trained or not hasattr(self.model, 'feature_importances_'):
            return {f: 1.0/len(FeatureExtractor.FEATURE_NAMES) for f in FeatureExtractor.FEATURE_NAMES}
        
        importances = self.model.feature_importances_
        return {
            name: round(float(imp), 4)
            for name, imp in zip(FeatureExtractor.FEATURE_NAMES, importances)
        }
