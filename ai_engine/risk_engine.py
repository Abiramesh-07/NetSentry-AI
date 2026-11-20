from config import Config
from database.models import SettingsModel

class RiskEngine:
    @staticmethod
    def calculate_risk(iso_score, rf_class, rf_confidence, behavior_eval, threat_intel_score=0, flow_dict=None):
        """
        Calculates a dynamic 0-100 risk score and severity level based on weighted factors.
        Returns risk score, severity string, and detailed contributing factor breakdown.
        """
        flow_dict = flow_dict or {}

        # Fetch active weights from settings or fallbacks
        w_iso = float(SettingsModel.get('isolation_weight', Config.RISK_WEIGHT_ISOLATION_FOREST))
        w_rf = float(SettingsModel.get('rf_weight', Config.RISK_WEIGHT_RANDOM_FOREST))
        w_beh = float(SettingsModel.get('behavior_weight', Config.RISK_WEIGHT_BEHAVIOR_DEVIATION))
        w_vol = float(SettingsModel.get('volume_weight', Config.RISK_WEIGHT_VOLUME_ANOMALY))
        w_rep = float(SettingsModel.get('reputation_weight', Config.RISK_WEIGHT_DEST_REPUTATION))

        # 1. Isolation Forest component (0 to 100)
        c_iso = iso_score * 100.0

        # 2. Random Forest component (0 to 100)
        # Weight depends on predicted class and confidence
        class_base_risk = {
            'Normal Traffic': 5.0,
            'Suspicious Outbound Transfer': 65.0,
            'Abnormal Connection Behavior': 55.0,
            'Potential Data Exfiltration': 92.0
        }
        base_rf = class_base_risk.get(rf_class, 20.0)
        c_rf = base_rf * rf_confidence

        # 3. Behavioral deviation component (0 to 100)
        beh_score = behavior_eval.get('behavior_deviation_score', 0.0)
        c_beh = beh_score * 100.0

        # 4. Outbound Volume component (0 to 100)
        bytes_sent = float(flow_dict.get('bytes_sent', 0))
        vol_mult = behavior_eval.get('volume_multiplier', 1.0)
        if bytes_sent > 10000000 or vol_mult > 10.0:  # >10MB or 10x baseline
            c_vol = 95.0
        elif bytes_sent > 2000000 or vol_mult > 4.0:   # >2MB or 4x baseline
            c_vol = 75.0
        elif bytes_sent > 500000 or vol_mult > 2.0:
            c_vol = 50.0
        elif bytes_sent > 100000:
            c_vol = 25.0
        else:
            c_vol = 5.0

        # 5. Destination Reputation component (0 to 100)
        c_rep = float(threat_intel_score)

        # Calculate composite score
        total_weight = w_iso + w_rf + w_beh + w_vol + w_rep
        raw_risk = (
            (c_iso * w_iso) +
            (c_rf * w_rf) +
            (c_beh * w_beh) +
            (c_vol * w_vol) +
            (c_rep * w_rep)
        ) / total_weight

        # Specific multiplier boosts for critical combinations
        # e.g., Potential Data Exfiltration + High Outbound Volume is prioritized
        if rf_class == 'Potential Data Exfiltration':
            raw_risk = max(raw_risk, 76.0 if bytes_sent < 1000000 else 91.0)
        elif rf_class == 'Suspicious Outbound Transfer':
            raw_risk = max(raw_risk, 62.0)
        elif rf_class == 'Abnormal Connection Behavior' and c_iso > 60:
            raw_risk = max(raw_risk, 55.0)

        if c_rep >= 80:
            raw_risk = max(raw_risk, 80.0)

        risk_score = round(min(100.0, max(0.0, raw_risk)), 1)

        # Severity mapping
        if risk_score >= Config.RISK_THRESHOLD_HIGH:
            severity = 'Critical'
        elif risk_score >= Config.RISK_THRESHOLD_MEDIUM:
            severity = 'High'
        elif risk_score >= Config.RISK_THRESHOLD_LOW:
            severity = 'Medium'
        else:
            severity = 'Low'

        # Detailed breakdown for UI transparency
        factors_breakdown = {
            'isolation_forest': {
                'weight': w_iso,
                'sub_score': round(c_iso, 1),
                'contribution': round((c_iso * w_iso) / total_weight, 1)
            },
            'random_forest': {
                'weight': w_rf,
                'sub_score': round(c_rf, 1),
                'contribution': round((c_rf * w_rf) / total_weight, 1)
            },
            'behavior_deviation': {
                'weight': w_beh,
                'sub_score': round(c_beh, 1),
                'contribution': round((c_beh * w_beh) / total_weight, 1)
            },
            'volume_anomaly': {
                'weight': w_vol,
                'sub_score': round(c_vol, 1),
                'contribution': round((c_vol * w_vol) / total_weight, 1)
            },
            'destination_reputation': {
                'weight': w_rep,
                'sub_score': round(c_rep, 1),
                'contribution': round((c_rep * w_rep) / total_weight, 1)
            }
        }

        return risk_score, severity, factors_breakdown
