import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap
from config import Config

def set_time(pkt, timestamp):
    pkt.time = float(timestamp)
    return pkt

def generate_sample_pcaps():
    """
    Generates three authentic, Wireshark-compatible PCAP files:
    1. normal_workstation_traffic.pcap
    2. data_exfiltration_incident.pcap
    3. dns_tunneling_and_c2.pcap
    """
    os.makedirs(Config.SAMPLE_PCAP_FOLDER, exist_ok=True)

    # -------------------------------------------------------------
    # 1. Normal Workstation Traffic PCAP
    # -------------------------------------------------------------
    normal_pkts = []
    base_time = 1731510000.0

    # DNS lookup to 8.8.8.8
    dns_query = set_time(
        IP(src="192.168.1.105", dst="8.8.8.8") /
        UDP(sport=53412, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="www.github.com")),
        base_time
    )
    dns_resp = set_time(
        IP(src="8.8.8.8", dst="192.168.1.105") /
        UDP(sport=53, dport=53412) /
        Raw(load=b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x06github\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x8c\x52\x24\x04"),
        base_time + 0.02
    )
    normal_pkts.extend([dns_query, dns_resp])

    # HTTPS handshake & standard web exchange with GitHub (140.82.36.4)
    syn = set_time(IP(src="192.168.1.105", dst="140.82.36.4") / TCP(sport=49160, dport=443, flags="S", seq=1000), base_time + 0.05)
    syn_ack = set_time(IP(src="140.82.36.4", dst="192.168.1.105") / TCP(sport=443, dport=49160, flags="SA", seq=5000, ack=1001), base_time + 0.08)
    ack = set_time(IP(src="192.168.1.105", dst="140.82.36.4") / TCP(sport=49160, dport=443, flags="A", seq=1001, ack=5001), base_time + 0.09)
    normal_pkts.extend([syn, syn_ack, ack])

    # Client hello (outbound small request ~400 bytes)
    tls_req = set_time(
        IP(src="192.168.1.105", dst="140.82.36.4") /
        TCP(sport=49160, dport=443, flags="PA", seq=1001, ack=5001) /
        Raw(load=b"\x16\x03\x01\x01\x20" + b"\x00" * 300),
        base_time + 0.12
    )
    normal_pkts.append(tls_req)

    # Server TLS response (inbound heavy data ~1400 bytes packets)
    for i in range(12):
        tls_data = set_time(
            IP(src="140.82.36.4", dst="192.168.1.105") /
            TCP(sport=443, dport=49160, flags="PA", seq=5001 + i*1400, ack=1306) /
            Raw(load=b"\x17\x03\x03\x05\x50" + (f"NORMAL_INBOUND_PAYLOAD_CHUNK_{i}".encode() * 40)[:1350]),
            base_time + 0.15 + i*0.01
        )
        normal_pkts.append(tls_data)

    normal_path = os.path.join(Config.SAMPLE_PCAP_FOLDER, 'normal_workstation_traffic.pcap')
    wrpcap(normal_path, normal_pkts)

    # -------------------------------------------------------------
    # 2. Potential Data Exfiltration PCAP
    # -------------------------------------------------------------
    exfil_pkts = []
    exfil_time = 1731520000.0

    # Background packets
    exfil_pkts.append(set_time(IP(src="192.168.1.142", dst="1.1.1.1") / UDP(sport=51234, dport=53) / DNS(rd=1, qd=DNSQR(qname="cloud-update.internal")), exfil_time))
    exfil_pkts.append(set_time(IP(src="1.1.1.1", dst="192.168.1.142") / UDP(sport=53, dport=51234) / Raw(load=b"DNS_RESP"), exfil_time + 0.03))

    # Bulk HTTPS POST data exfiltration to offshore external IP (198.51.100.77)
    e_syn = set_time(IP(src="192.168.1.142", dst="198.51.100.77") / TCP(sport=58810, dport=8443, flags="S", seq=2000), exfil_time + 0.10)
    e_synack = set_time(IP(src="198.51.100.77", dst="192.168.1.142") / TCP(sport=8443, dport=58810, flags="SA", seq=9000, ack=2001), exfil_time + 0.15)
    e_ack = set_time(IP(src="192.168.1.142", dst="198.51.100.77") / TCP(sport=58810, dport=8443, flags="A", seq=2001, ack=9001), exfil_time + 0.16)
    exfil_pkts.extend([e_syn, e_synack, e_ack])

    for i in range(45):
        chunk = set_time(
            IP(src="192.168.1.142", dst="198.51.100.77") /
            TCP(sport=58810, dport=8443, flags="PA", seq=2001 + i*1460, ack=9001) /
            Raw(load=b"POST /api/upload/financial_archive.tar.gz HTTP/1.1\r\nContent-Type: application/octet-stream\r\n" + (b"EXFILTRATED_CONFIDENTIAL_DB_DUMP_" * 45)[:1380]),
            exfil_time + 0.20 + i*0.02
        )
        exfil_pkts.append(chunk)

    exfil_pkts.append(set_time(IP(src="198.51.100.77", dst="192.168.1.142") / TCP(sport=8443, dport=58810, flags="A", seq=9001, ack=65000), exfil_time + 1.2))

    exfil_path = os.path.join(Config.SAMPLE_PCAP_FOLDER, 'data_exfiltration_incident.pcap')
    wrpcap(exfil_path, exfil_pkts)

    # -------------------------------------------------------------
    # 3. DNS Tunneling & C2 Beaconing PCAP
    # -------------------------------------------------------------
    tunnel_pkts = []
    tun_time = 1731530000.0

    encoded_chunks = [
        "4a7f8e12b9c3d4e5f6a1b2c3d4e5f6a7.tunnel.c2-exfil.xyz",
        "89ab4cde5f6a7b8c9d0e1f2a3b4c5d6e.tunnel.c2-exfil.xyz",
        "deadbeef1234567890abcdef12345678.tunnel.c2-exfil.xyz",
        "77617374656c616e645f736563726574.tunnel.c2-exfil.xyz",
        "6b65796c6f676765725f64756d703031.tunnel.c2-exfil.xyz",
        "73616d5f64617461626173655f686173.tunnel.c2-exfil.xyz"
    ]

    for idx, subdomain in enumerate(encoded_chunks):
        t_req = set_time(
            IP(src="192.168.1.189", dst="203.0.113.88") /
            UDP(sport=48000 + idx, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=subdomain, qtype=16)),
            tun_time + idx * 0.2
        )
        t_res = set_time(
            IP(src="203.0.113.88", dst="192.168.1.189") /
            UDP(sport=53, dport=48000 + idx) /
            Raw(load=b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00ACK_RECV"),
            tun_time + idx * 0.2 + 0.05
        )
        tunnel_pkts.extend([t_req, t_res])

    for b in range(5):
        beacon = set_time(
            IP(src="192.168.1.189", dst="203.0.113.88") /
            TCP(sport=51000 + b, dport=4444, flags="PA", seq=100 + b*64) /
            Raw(load=b"HEARTBEAT_BEACON_AGENT_ID=4921_STATUS=IDLE\n"),
            tun_time + 5.0 + b * 2.0
        )
        tunnel_pkts.append(beacon)

    tun_path = os.path.join(Config.SAMPLE_PCAP_FOLDER, 'dns_tunneling_and_c2.pcap')
    wrpcap(tun_path, tunnel_pkts)

    print(f"[NetSentry AI] Generated 3 sample PCAP files in {Config.SAMPLE_PCAP_FOLDER}:")
    print(f"  - {normal_path} ({len(normal_pkts)} packets)")
    print(f"  - {exfil_path} ({len(exfil_pkts)} packets)")
    print(f"  - {tun_path} ({len(tunnel_pkts)} packets)")

if __name__ == '__main__':
    generate_sample_pcaps()
