import requests

def get_public_ip():
    """Fetch the public IP of the scanner."""
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        if response.status_code == 200:
            return response.json().get('ip', 'Unknown')
    except Exception:
        pass
    return 'Unknown'
