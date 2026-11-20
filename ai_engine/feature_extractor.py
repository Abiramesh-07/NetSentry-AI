import numpy as np
from datetime import datetime

class FeatureExtractor:
    FEATURE_NAMES = [
        'bytes_sent',
        'bytes_recv',
        'outbound_inbound_ratio',
        'packet_count',
        'duration',
        'bytes_per_second',
        'packets_per_second',
        'avg_packet_size',
        'dst_port',
        'protocol_code',
        'hour_of_day',
        'is_sensitive_port',
        'is_outbound_dominant'
    ]

    SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 4444, 6667, 8080, 8443, 9001}

    @staticmethod
    def extract_from_flow(flow):
        """
        Extracts a normalized 13-feature numerical vector from a network flow dict/record.
        """
        bytes_sent = float(flow.get('bytes_sent', 0))
        bytes_recv = float(flow.get('bytes_recv', 0))
        total_bytes = bytes_sent + bytes_recv
        packets_sent = float(flow.get('packets_sent', 1))
        packets_recv = float(flow.get('packets_recv', 1))
        packet_count = packets_sent + packets_recv
        duration = max(float(flow.get('duration', 0.1)), 0.001)

        # Ratios & rates
        ratio = bytes_sent / (total_bytes + 1.0)
        bytes_per_sec = total_bytes / duration
        packets_per_sec = packet_count / duration
        avg_packet_size = total_bytes / max(packet_count, 1.0)

        dst_port = int(flow.get('dst_port', 0))

        # Protocol mapping
        proto_str = str(flow.get('protocol', 'TCP')).upper()
        if 'TCP' in proto_str:
            proto_code = 6
        elif 'UDP' in proto_str:
            proto_code = 17
        elif 'ICMP' in proto_str:
            proto_code = 1
        else:
            proto_code = 0

        # Time feature
        ts = flow.get('timestamp')
        if isinstance(ts, str):
            try:
                dt = datetime.strptime(ts.split('.')[0], "%Y-%m-%d %H:%M:%S")
                hour = dt.hour
            except Exception:
                hour = datetime.utcnow().hour
        elif isinstance(ts, datetime):
            hour = ts.hour
        else:
            hour = datetime.utcnow().hour

        is_sensitive = 1.0 if dst_port in FeatureExtractor.SENSITIVE_PORTS else 0.0
        is_outbound_dominant = 1.0 if ratio > 0.8 else 0.0

        features = [
            bytes_sent,
            bytes_recv,
            ratio,
            packet_count,
            duration,
            bytes_per_sec,
            packets_per_sec,
            avg_packet_size,
            float(dst_port),
            float(proto_code),
            float(hour),
            is_sensitive,
            is_outbound_dominant
        ]

        return np.array(features, dtype=np.float64)

    @staticmethod
    def extract_dict(flow):
        feats = FeatureExtractor.extract_from_flow(flow)
        return dict(zip(FeatureExtractor.FEATURE_NAMES, feats.tolist()))
