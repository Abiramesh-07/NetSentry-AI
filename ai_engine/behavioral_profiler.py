from database.models import DeviceProfileModel

class BehavioralProfiler:
    @staticmethod
    def evaluate_flow_against_baseline(flow_dict):
        """
        Compares an incoming flow with the device's historical baseline profile.
        Returns deviation metrics, z-scores, and a normalized behavior risk deviation factor (0.0 to 1.0).
        """
        src_ip = flow_dict.get('src_ip', '0.0.0.0')
        profile = DeviceProfileModel.get_or_create(src_ip)

        bytes_sent = float(flow_dict.get('bytes_sent', 0))
        ratio = float(flow_dict.get('outbound_inbound_ratio', 0.5))
        duration = float(flow_dict.get('duration', 0.1))

        avg_bytes = float(profile['avg_bytes_sent'])
        std_bytes = max(float(profile['std_bytes_sent']), 5000.0)
        avg_ratio = float(profile['avg_ratio'])

        # Calculate deviation in outbound volume
        volume_multiplier = bytes_sent / max(avg_bytes, 1.0)
        z_score_volume = (bytes_sent - avg_bytes) / std_bytes

        # Calculate deviation in ratio (e.g. baseline is 0.40, current flow is 0.95)
        ratio_diff = max(0.0, ratio - avg_ratio)

        # Time of day deviation check
        import datetime
        now_hour = datetime.datetime.utcnow().hour
        peak_start = profile['peak_hour_start']
        peak_end = profile['peak_hour_end']
        is_off_hours = not (peak_start <= now_hour <= peak_end)

        # Composite behavioral deviation score (0.0 to 1.0)
        dev_score = 0.0

        # Volume contribution
        if volume_multiplier > 5.0:
            dev_score += 0.45
        elif volume_multiplier > 2.5:
            dev_score += 0.25
        elif volume_multiplier > 1.5:
            dev_score += 0.10

        # Ratio contribution
        if ratio_diff > 0.4:
            dev_score += 0.30
        elif ratio_diff > 0.2:
            dev_score += 0.15

        # Off hours activity contribution
        if is_off_hours and volume_multiplier > 2.0:
            dev_score += 0.20
        elif is_off_hours:
            dev_score += 0.05

        dev_score = min(1.0, max(0.0, dev_score))

        return {
            'device_ip': src_ip,
            'hostname': profile['hostname'],
            'total_flows_analyzed': profile['total_flows_analyzed'],
            'baseline_avg_bytes': round(avg_bytes, 1),
            'current_bytes_sent': round(bytes_sent, 1),
            'volume_multiplier': round(volume_multiplier, 2),
            'z_score_volume': round(z_score_volume, 2),
            'baseline_avg_ratio': round(avg_ratio, 3),
            'current_ratio': round(ratio, 3),
            'is_off_hours': is_off_hours,
            'behavior_deviation_score': round(dev_score, 4)
        }

    @staticmethod
    def update_baseline_with_validated_normal(device_ip, bytes_sent, ratio):
        """
        Strictly updates baseline with analyst-verified normal traffic.
        Safeguards against poisoning baseline with malicious behavior.
        """
        DeviceProfileModel.update_baseline_from_validated_normal(device_ip, bytes_sent, ratio)
