import numpy as np
from ai_engine.feature_extractor import FeatureExtractor

class ExplainableAI:
    @staticmethod
    def generate_explanation(flow_dict, iso_score, rf_class, rf_confidence, rf_probs, behavior_eval, risk_score, severity):
        """
        Produces detailed, transparent, explainable feature attributions,
        deviation reasoning, and concrete SOC investigation steps.
        """
        bytes_sent = float(flow_dict.get('bytes_sent', 0))
        bytes_recv = float(flow_dict.get('bytes_recv', 0))
        ratio = float(flow_dict.get('outbound_inbound_ratio', 0.5))
        duration = float(flow_dict.get('duration', 0.1))
        dst_port = int(flow_dict.get('dst_port', 0))
        dst_ip = str(flow_dict.get('dst_ip', ''))

        vol_mult = behavior_eval.get('volume_multiplier', 1.0)
        baseline_bytes = behavior_eval.get('baseline_avg_bytes', 50000)
        is_off_hours = behavior_eval.get('is_off_hours', False)

        # 1. Feature Contribution Analysis
        # Calculate feature deviation percentage from standard normal network traffic reference
        feature_weights = []
        
        # Outbound byte volume impact
        if vol_mult > 1.5:
            contrib = min(0.40, (vol_mult - 1.0) * 0.08)
            feature_weights.append({
                'feature': 'Outbound Data Volume',
                'importance': round(contrib, 3),
                'direction': 'Elevated',
                'details': f"Transfer volume ({bytes_sent:,.0f} B) is {vol_mult:.1f}x higher than device baseline ({baseline_bytes:,.0f} B)."
            })

        # Outbound/Inbound Ratio impact
        if ratio > 0.75:
            contrib = (ratio - 0.5) * 0.5
            feature_weights.append({
                'feature': 'Outbound / Inbound Ratio',
                'importance': round(contrib, 3),
                'direction': 'Asymmetric Outbound',
                'details': f"{ratio*100:.1f}% of total flow data was outbound, indicating one-way exfiltration pattern rather than typical interactive browsing."
            })

        # Flow duration & bandwidth rate impact
        bytes_per_sec = (bytes_sent + bytes_recv) / max(duration, 0.01)
        if bytes_per_sec > 1000000:
            feature_weights.append({
                'feature': 'High Transfer Velocity',
                'importance': 0.22,
                'direction': 'High Bandwidth',
                'details': f"Sustained burst of {bytes_per_sec / (1024*1024):.2f} MB/s over {duration:.2f} seconds."
            })
        elif duration < 0.02 and bytes_sent > 10000:
            feature_weights.append({
                'feature': 'Abnormal Connection Spike',
                'importance': 0.18,
                'direction': 'Rapid Burst',
                'details': f"Abnormally brief connection window ({duration:.3f}s) for high data payload."
            })

        # Time of day impact
        if is_off_hours:
            feature_weights.append({
                'feature': 'Off-Hours Activity',
                'importance': 0.15,
                'direction': 'Anomalous Time',
                'details': "Activity occurred outside device's regular business operating hours."
            })

        # Destination port factor
        if dst_port in [53, 4444, 6667, 8080, 8443, 9001] or dst_port > 49152:
            feature_weights.append({
                'feature': 'Destination Port Sensitivity',
                'importance': 0.18,
                'direction': 'Unusual Port',
                'details': f"Outbound destination port {dst_port} frequently associated with tunnels or non-standard egress."
            })

        if not feature_weights:
            feature_weights.append({
                'feature': 'Standard Flow Characteristics',
                'importance': 0.05,
                'direction': 'Nominal',
                'details': 'Flow parameters are within expected operational tolerance limits.'
            })

        # Sort feature contributions by importance
        feature_weights.sort(key=lambda x: x['importance'], reverse=True)

        # 2. Executive Primary Reason
        if rf_class == 'Potential Data Exfiltration':
            primary_reason = f"Substantial outbound transfer volume ({bytes_sent:,.0f} B, {vol_mult:.1f}x baseline) with an asymmetric egress ratio ({ratio*100:.1f}%) sent to {dst_ip}."
        elif rf_class == 'Suspicious Outbound Transfer':
            primary_reason = f"Outbound transmission of {bytes_sent:,.0f} bytes deviates significantly from established baseline profile."
        elif rf_class == 'Abnormal Connection Behavior':
            primary_reason = f"Flow duration ({duration:.2f}s) and connection frequency to port {dst_port} exhibit abnormal signaling patterns."
        else:
            primary_reason = f"Flow aligns closely with typical enterprise workstation traffic baseline."

        # 3. Actionable SOC Recommendations
        recommendations = []
        if severity in ['High', 'Critical']:
            recommendations.append(f"1. Immediate Host Triage: Inspect host {flow_dict.get('src_ip')} for active background file transfer processes (e.g. curl, rclone, scp, PowerShell webclient).")
            recommendations.append(f"2. Network Containment: Evaluate temporarily restricting outbound egress to destination {dst_ip} on port {dst_port}.")
            recommendations.append(f"3. EDR / Process Inspection: Review process telemetry and parent-child command line executions around {flow_dict.get('timestamp')}.")
            recommendations.append("4. Baseline Validation: If this transfer is confirmed as an approved business backup or deployment, mark as 'Legitimate' to update device baseline profile.")
        elif severity == 'Medium':
            recommendations.append(f"1. Monitor Host: Observe subsequent outbound flow counts from {flow_dict.get('src_ip')}.")
            recommendations.append(f"2. Threat Intelligence Check: Cross-reference external IP {dst_ip} with current threat feeds.")
            recommendations.append("3. User Correlation: Verify if the user logged in at this host initiated large cloud storage uploads.")
        else:
            recommendations.append("1. Routine Logging: Continue monitoring device activity; no immediate intervention required.")

        return {
            'primary_reason': primary_reason,
            'feature_contributions': feature_weights,
            'isolation_forest_analysis': {
                'anomaly_score': iso_score,
                'interpretation': 'High multidimensional divergence from training cluster' if iso_score > 0.60 else 'Within nominal cluster distance'
            },
            'random_forest_analysis': {
                'predicted_class': rf_class,
                'confidence': f"{rf_confidence*100:.1f}%",
                'probabilities': rf_probs
            },
            'baseline_comparison': {
                'baseline_avg_bytes': baseline_bytes,
                'current_bytes': bytes_sent,
                'volume_multiplier': vol_mult,
                'is_off_hours': is_off_hours
            },
            'recommended_actions': recommendations,
            'safety_disclaimer': 'NetSentry AI classifies statistical deviations. Unusual outbound volume or connection patterns indicate potential data exfiltration requiring analyst investigation and do not constitute definitive proof of malicious data theft.'
        }
