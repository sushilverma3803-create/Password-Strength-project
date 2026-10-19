import hashlib
import requests
from typing import Dict, Any, Tuple

PWNED_PASSWORDS_API_URL = "https://api.pwnedpasswords.com/range/"

def check_hibp_pwned_api(password: str, timeout: float = 3.0) -> Tuple[bool, int, str]:
    """
    Check password against HaveIBeenPwned (HIBP) database using privacy-preserving k-Anonymity.
    Only the first 5 characters of the SHA-1 hash are sent over HTTPS.
    Returns: (is_breached: bool, breach_count: int, source_note: str)
    """
    if not password:
        return False, 0, "No password provided"

    # Compute uppercase SHA-1 hash
    sha1_full = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_full[:5]
    suffix = sha1_full[5:]

    try:
        url = f"{PWNED_PASSWORDS_API_URL}{prefix}"
        headers = {
            'User-Agent': 'CyberGuard-Password-Security-Sentinel/2.0',
            'Add-Padding': 'true'  # Minimizes response size correlation attacks
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                parts = line.strip().split(':')
                if len(parts) == 2 and parts[0].upper() == suffix:
                    count = int(parts[1])
                    return True, count, "HaveIBeenPwned API (k-Anonymity Verified)"

            return False, 0, "HaveIBeenPwned API (Zero Breaches Found)"
        else:
            return False, 0, f"HIBP API returned status {response.status_code}"
    except Exception as e:
        return False, 0, f"HIBP API connection fallback: {str(e)}"


def check_password_breach(password: str, db_session=None, compromised_model=None) -> Dict[str, Any]:
    """
    Comprehensive breach detection combining HIBP k-Anonymity API with local SQLite lookup.
    """
    if not password:
        return {
            'is_breached': False,
            'count': 0,
            'source': 'None',
            'warning': None
        }

    # 1. First check via HIBP API (Live Global Intelligence)
    is_pwned, count, source = check_hibp_pwned_api(password)
    if is_pwned and count > 0:
        return {
            'is_breached': True,
            'count': count,
            'source': source,
            'warning': f"CRITICAL: Found in {count:,} known data leaks according to HaveIBeenPwned!"
        }

    # 2. Local fallback check in SQLite CompromisedPassword table
    if db_session and compromised_model:
        try:
            sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            local_match = compromised_model.query.filter(
                (compromised_model.sha256_hash == sha256_hash) |
                (compromised_model.plain_text == password.lower())
            ).first()

            if local_match:
                return {
                    'is_breached': True,
                    'count': 1,
                    'source': f"Local SQLite Threat Shield ({local_match.category})",
                    'warning': f"CRITICAL: Matched known compromised dictionary list ({local_match.category})!"
                }
        except Exception:
            pass

    return {
        'is_breached': False,
        'count': 0,
        'source': source if "API" in source else "Local Verification Clean",
        'warning': None
    }

# Explicit aliases for modular testing & integration
check_breach_hibp_k_anonymity = check_hibp_pwned_api

def check_breach_local(password: str, db_session=None, compromised_model=None) -> Tuple[bool, int, str]:
    """
    Check password against local compromised signatures/dictionary.
    Returns: (is_breached: bool, count: int, source: str)
    """
    if not password:
        return False, 0, "Empty password"

    # Known common passwords list for instantaneous offline fallback
    LOCAL_KNOWN_PWDS = {
        'password', '123456', '12345678', 'qwerty', '111111', '12345', '123456789',
        'password1', 'admin', 'welcome', 'login', 'root', 'guest', 'iloveyou'
    }

    if password.lower() in LOCAL_KNOWN_PWDS:
        return True, 5000000, "Local Compromised Signatures"

    if db_session and compromised_model:
        try:
            sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            local_match = compromised_model.query.filter(
                (compromised_model.sha256_hash == sha256_hash) |
                (compromised_model.plain_text == password.lower())
            ).first()
            if local_match:
                return True, 10000, f"Local SQLite Threat Shield ({local_match.category})"
        except Exception:
            pass

    return False, 0, "Local Signatures Clean"

