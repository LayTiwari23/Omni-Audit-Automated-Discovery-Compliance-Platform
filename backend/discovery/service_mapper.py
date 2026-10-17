SERVICE_TO_ENGINE = {
    'http': 'web_engine',
    'https': 'web_engine',
    'web': 'web_engine',
    'dns': 'dns_engine',
    'smtp': 'email_engine',
    'email': 'email_engine',
    'ssh': 'ssh_engine',
    'ftp': 'ftp_engine',
    'isakmp': 'vpn_engine',
    'ipsec-nat-t': 'vpn_engine',
    'openvpn': 'vpn_engine',
    'pptp': 'vpn_engine',
    'l2tp': 'vpn_engine',
    'network': 'network_engine',
}

def map_services_to_engines(services: list) -> list:
    """Convert service names to engine names."""
    engines = set()
    for s in services:
        engine = SERVICE_TO_ENGINE.get(s)
        if engine:
            engines.add(engine)
    return list(engines)