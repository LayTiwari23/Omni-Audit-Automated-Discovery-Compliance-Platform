### **File 2: `backend/app/utils/domain_validator.py`**
"""
Domain validation utilities.
Validates domain before scan starts.
"""

import socket
import requests
from typing import Tuple


def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate domain before starting scan.
    
    Returns:
        (is_valid, error_message)
    """
    # Clean domain
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0].strip()
    
    if not domain:
        return False, "Domain cannot be empty"
    
    # DNS validation
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return False, f"Domain '{domain}' does not resolve (DNS lookup failed)"
    except Exception as e:
        return False, f"DNS error: {str(e)}"
    
    return True, ""


def is_domain_reachable(domain: str, timeout: int = 10) -> Tuple[bool, str]:
    """
    Check if domain is reachable via HTTP/HTTPS.
    
    Returns:
        (is_reachable, error_message)
    """
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0].strip()
    
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return True, f"Reachable via {protocol.upper()}"
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue
    
    return False, "Domain not reachable via HTTP or HTTPS"

