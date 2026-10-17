"""
cvss_service.py – Fetches CVSS scores from free APIs with caching.
"""

import asyncio
import aiohttp
import logging
from typing import Optional, Tuple
import json
import redis
import os

from . import cvss_mapping

logger = logging.getLogger(__name__)

# Redis client for caching
redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))

# API endpoints
SHODAN_CVEDB = "https://cvedb.shodan.io/cve/{}"
CIRCL_API = "https://cve.circl.lu/api/cve/{}"

def severity_from_score(score: float) -> str:
    """Convert CVSS score to severity string."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return ""

async def fetch_cve_from_shodan(session: aiohttp.ClientSession, cve_id: str) -> Optional[dict]:
    """Fetch CVE data from Shodan CVEDB."""
    try:
        async with session.get(SHODAN_CVEDB.format(cve_id), timeout=5) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {
                    "cvss": data.get('cvss', 0.0),
                    "severity": severity_from_score(data.get('cvss', 0.0)),
                    "epss": data.get('epss', 0.0),
                    "kev": data.get('kev', False),
                    "source": "shodan"
                }
    except Exception as e:
        logger.debug(f"Shodan CVEDB failed for {cve_id}: {e}")
    return None

async def fetch_cve_from_circl(session: aiohttp.ClientSession, cve_id: str) -> Optional[dict]:
    """Fallback to CIRCL CVE search."""
    try:
        async with session.get(CIRCL_API.format(cve_id), timeout=5) as resp:
            if resp.status == 200:
                data = await resp.json()
                cvss_v3 = data.get('cvss', 0.0)
                if not cvss_v3:
                    cvss_v3 = data.get('cvss2', {}).get('score', 0.0)
                return {
                    "cvss": cvss_v3,
                    "severity": severity_from_score(cvss_v3),
                    "source": "circl"
                }
    except Exception as e:
        logger.debug(f"CIRCL API failed for {cve_id}: {e}")
    return None

async def get_cvss_for_cve(cve_id: str) -> dict:
    """
    Fetch CVSS for a CVE ID using free APIs with fallback.
    Results are cached in Redis for 24 hours.
    """
    cache_key = f"cve:{cve_id}"
    
    # Check cache
    try:
        cached = redis_client.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception as e:
        logger.warning(f"Redis error: {e}")
    
    # Try APIs
    async with aiohttp.ClientSession() as session:
        # Try Shodan first (fastest, most reliable)
        result = await fetch_cve_from_shodan(session, cve_id)
        if not result:
            # Fallback to CIRCL
            result = await fetch_cve_from_circl(session, cve_id)
    
    if result:
        # Cache for 24 hours
        try:
            redis_client.setex(cache_key, 86400, json.dumps(result))
        except Exception as e:
            logger.warning(f"Redis cache failed: {e}")
        return result
    
    # If all APIs fail, return default
    return {"cvss": 5.0, "severity": "MEDIUM", "source": "default"}

def get_cvss_for_check(check_id: int, check_name: str = None) -> dict:
    """
    Main function to get CVSS data for a compliance check.
    Uses local mapping, with API lookup for checks that have CVE IDs.
    """
    # Get local mapping first
    local = cvss_mapping.get_local_severity(check_id)
    
    # If this check has a CVE ID, try API lookup
    if 'cve' in local:
        # Run async API call in sync context
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        try:
            api_result = loop.run_until_complete(get_cvss_for_cve(local['cve']))
            # Override with API data if successful
            if api_result.get('source') != 'default':
                return {
                    "cvss_score": api_result['cvss'],
                    "severity": api_result['severity'],
                    "description": local['description'],
                    "cve_id": local['cve']
                }
        except Exception as e:
            logger.error(f"Error fetching CVSS for {local['cve']}: {e}")
        finally:
            if not loop.is_running():
                pass # Don't close loop if it's the main one
    
    # Return local mapping
    return {
        "cvss_score": local['cvss'],
        "severity": local['severity'],
        "description": local['description'],
        "cve_id": local.get('cve')
    }