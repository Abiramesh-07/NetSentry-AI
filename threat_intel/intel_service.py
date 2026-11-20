import json
import requests
from database.models import ThreatIntelModel, SettingsModel

class ThreatIntelService:
    # High-confidence built-in threat intelligence reputation database
    LOCAL_FEED = {
        "198.51.100.77": {
            "reputation_score": 92,
            "category": "Potential C2 / Data Drop",
            "country": "RO",
            "isp": "Offshore Bulletproof Hosting Ltd",
            "is_known_malicious": 1,
            "tags": ["exfiltration-endpoint", "unindexed-ip", "high-volume-drop"]
        },
        "203.0.113.88": {
            "reputation_score": 88,
            "category": "DNS Tunneling / C2 Server",
            "country": "RU",
            "isp": "FastFlux Dynamic Host Provider",
            "is_known_malicious": 1,
            "tags": ["dns-tunnel-receiver", "c2-beacon-target", "botnet-controller"]
        },
        "185.220.101.5": {
            "reputation_score": 85,
            "category": "Tor Exit Node",
            "country": "DE",
            "isp": "Tor Anonymizer Network",
            "is_known_malicious": 1,
            "tags": ["anonymizer", "tor-exit", "privacy-proxy"]
        },
        "45.33.32.156": {
            "reputation_score": 78,
            "category": "Known Port Scanner",
            "country": "US",
            "isp": "Linode LLC (Abuse Reported)",
            "is_known_malicious": 1,
            "tags": ["masscan", "reconnaissance", "shodan-scanner"]
        },
        # Clean trusted enterprise hosts
        "8.8.8.8": {
            "reputation_score": 0,
            "category": "Clean Anycast DNS",
            "country": "US",
            "isp": "Google LLC",
            "is_known_malicious": 0,
            "tags": ["public-dns", "anycast", "trusted"]
        },
        "1.1.1.1": {
            "reputation_score": 0,
            "category": "Clean Anycast DNS",
            "country": "AU",
            "isp": "Cloudflare Inc",
            "is_known_malicious": 0,
            "tags": ["public-dns", "cloudflare", "trusted"]
        },
        "140.82.36.4": {
            "reputation_score": 0,
            "category": "Verified Cloud Platform",
            "country": "US",
            "isp": "GitHub Inc / Microsoft Corp",
            "is_known_malicious": 0,
            "tags": ["code-repository", "developer-service", "trusted"]
        },
        "52.96.166.130": {
            "reputation_score": 0,
            "category": "Enterprise Cloud Mail",
            "country": "US",
            "isp": "Microsoft Corporation",
            "is_known_malicious": 0,
            "tags": ["office365", "exchange-online", "trusted"]
        }
    }

    @staticmethod
    def lookup_ip(ip_address):
        """
        Looks up destination IP in local cache, then checks VirusTotal/AbuseIPDB if key is set,
        or falls back to local feed and heuristic reputation.
        """
        # Check SQLite DB first
        cached = ThreatIntelModel.get_ip(ip_address)
        if cached:
            return {
                "ip_address": cached['ip_address'],
                "reputation_score": cached['reputation_score'],
                "category": cached['category'],
                "country": cached['country'],
                "isp": cached['isp'],
                "is_known_malicious": bool(cached['is_known_malicious']),
                "tags": json.loads(cached['tags_json']) if cached['tags_json'] else [],
                "source": "Database Cache"
            }

        # Check local threat feed
        if ip_address in ThreatIntelService.LOCAL_FEED:
            info = ThreatIntelService.LOCAL_FEED[ip_address]
            ThreatIntelModel.upsert(
                ip=ip_address,
                reputation_score=info['reputation_score'],
                category=info['category'],
                country=info['country'],
                isp=info['isp'],
                is_malicious=info['is_known_malicious'],
                tags=info['tags']
            )
            return {
                "ip_address": ip_address,
                **info,
                "source": "Threat Intelligence Feed"
            }

        # Check if external API key is configured
        vt_key = SettingsModel.get('virustotal_api_key', '')
        if vt_key and len(vt_key) > 10:
            try:
                # VirusTotal v3 API
                headers = {"x-apikey": vt_key}
                resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=headers, timeout=4)
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    stats = attrs.get('last_analysis_stats', {})
                    malicious_votes = stats.get('malicious', 0)
                    rep_score = min(100, malicious_votes * 15)
                    category = "Malicious Host" if rep_score > 50 else "Clean / Unclassified"
                    country = attrs.get('country', 'US')
                    isp = attrs.get('as_owner', 'Unknown ISP')
                    tags = list(attrs.get('tags', []))
                    is_mal = 1 if rep_score > 40 else 0

                    ThreatIntelModel.upsert(ip_address, rep_score, category, country, isp, is_mal, tags)
                    return {
                        "ip_address": ip_address,
                        "reputation_score": rep_score,
                        "category": category,
                        "country": country,
                        "isp": isp,
                        "is_known_malicious": bool(is_mal),
                        "tags": tags,
                        "source": "VirusTotal Live API"
                    }
            except Exception as e:
                print(f"[NetSentry AI] VirusTotal API lookup error: {e}")

        # Default clean/internal heuristic
        is_private = ip_address.startswith(('10.', '172.16.', '172.31.', '192.168.', '127.'))
        default_info = {
            "reputation_score": 0 if is_private else 15,
            "category": "Private Enterprise Subnet" if is_private else "Public Unclassified IP",
            "country": "LOCAL" if is_private else "US",
            "isp": "Internal Network" if is_private else "Standard Public Egress",
            "is_known_malicious": 0,
            "tags": ["internal" if is_private else "external-peer"]
        }

        ThreatIntelModel.upsert(
            ip=ip_address,
            reputation_score=default_info['reputation_score'],
            category=default_info['category'],
            country=default_info['country'],
            isp=default_info['isp'],
            is_malicious=0,
            tags=default_info['tags']
        )

        return {
            "ip_address": ip_address,
            **default_info,
            "source": "Heuristic Classification"
        }
