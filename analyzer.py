import math
import re
import string

# -------------------------------------------------------------------------
# Pattern Databases & Keyboard Layouts
# -------------------------------------------------------------------------

KEYBOARD_ROWS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890',
    'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz', '0987654321',
    '789', '456', '123', '987', '654', '321', '741', '852', '963'
]

KEYBOARD_DIAGONALS = [
    '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik', '9ol', '0p',
    'zaq1', 'xsw2', 'cde3', 'vfr4', 'bgt5', 'nhy6', 'mju7'
]

COMMON_PASSWORDS_SET = {
    '123456', 'password', '123456789', '12345', '12345678', 'qwerty',
    '1234567', '111111', '1234567890', '123123', 'password1', 'welcome',
    'admin', 'iloveyou', 'princess', 'football', 'monkey', 'sunshine',
    'master', 'shadow', 'superman', 'starwars', 'secret', 'testing',
    'pass123', 'admin123', 'login', 'root', 'guest', 'charlie',
    'letmein', 'trustno1', 'dragon', 'baseball', 'killer', 'orange',
    'access', 'account', 'system', 'default', 'security', 'matrix',
    'batman', 'hunter', 'wizard', 'ranger', 'cookie', 'coffee',
    'spring', 'summer', 'autumn', 'winter', 'freedom', 'computer'
}

DICTIONARY_WORDS = [
    'password', 'admin', 'welcome', 'login', 'master', 'secret',
    'system', 'shadow', 'monkey', 'dragon', 'football', 'baseball',
    'princess', 'iloveyou', 'testing', 'sunshine', 'computer', 'access',
    'account', 'server', 'security', 'winter', 'summer', 'spring',
    'autumn', 'starwars', 'superman', 'batman', 'hunter', 'trustno1',
    'ranger', 'cookie', 'killer', 'matrix', 'falcon', 'wizard',
    'shield', 'danger', 'coffee', 'orange', 'purple', 'yellow'
]

LEET_MAP = {
    '@': 'a', '4': 'a', '8': 'b', '3': 'e', '1': 'i', '!': 'i',
    '|': 'i', '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't'
}

def normalize_leetspeak(text: str) -> str:
    """Translates common leetspeak substitutions back to standard characters."""
    return "".join(LEET_MAP.get(ch, ch) for ch in text.lower())


# -------------------------------------------------------------------------
# Pattern & Vulnerability Detection
# -------------------------------------------------------------------------

def detect_common_password(password: str, is_known_breached: bool = False) -> list[dict]:
    """Detect if password matches known common leaked passwords."""
    warnings = []
    lower_pwd = password.lower().strip()

    if lower_pwd in COMMON_PASSWORDS_SET or is_known_breached:
        warnings.append({
            'category': 'Common Password',
            'severity': 'critical',
            'message': f"CRITICAL: '{password}' is one of the most frequently breached passwords. Attackers test this instantly."
        })
    elif any(common in lower_pwd for common in ['password', 'admin123', 'pass123', 'qwerty123']):
        warnings.append({
            'category': 'Common Password',
            'severity': 'high',
            'message': "Contains an obvious, high-frequency compromised password prefix/suffix."
        })
    return warnings


def detect_repeated_characters(password: str) -> list[dict]:
    """Detect consecutive identical characters and repeating substring patterns."""
    warnings = []
    matches = re.findall(r'(.)\1{2,}', password)
    if matches:
        warnings.append({
            'category': 'Repeated Characters',
            'severity': 'high',
            'message': f"Consecutive repeated characters detected (e.g. '{matches[0]*3}'). Repetition drastically lowers entropy."
        })

    for chunk_len in [2, 3, 4]:
        for i in range(len(password) - chunk_len * 2 + 1):
            chunk = password[i:i+chunk_len]
            next_chunk = password[i+chunk_len:i+chunk_len*2]
            if chunk == next_chunk and len(chunk) > 1:
                warnings.append({
                    'category': 'Repeated Characters',
                    'severity': 'medium',
                    'message': f"Repeating sequence detected ('{chunk}{next_chunk}'). Repeating blocks can be cracked in quadratic time."
                })
                return warnings
    return warnings


def detect_sequential_patterns(password: str) -> list[dict]:
    """Detect numeric (123456) and alphabetical (abcdef) sequential runs."""
    warnings = []
    lower_pwd = password.lower()

    # Numeric sequence
    for i in range(len(password) - 2):
        chunk = password[i:i+3]
        if chunk.isdigit():
            c1, c2, c3 = int(chunk[0]), int(chunk[1]), int(chunk[2])
            if (c2 == (c1 + 1) % 10) and (c3 == (c2 + 1) % 10):
                warnings.append({
                    'category': 'Sequential Pattern',
                    'severity': 'high',
                    'message': f"Sequential numerical pattern detected ('{chunk}'). Attack tools prioritize sequential number generators."
                })
                break
            elif (c2 == (c1 - 1) % 10) and (c3 == (c2 - 1) % 10):
                warnings.append({
                    'category': 'Sequential Pattern',
                    'severity': 'high',
                    'message': f"Reverse sequential numerical pattern detected ('{chunk}')."
                })
                break

    # Alphabetical sequence
    alphabet = string.ascii_lowercase
    rev_alphabet = alphabet[::-1]
    for i in range(len(lower_pwd) - 2):
        chunk = lower_pwd[i:i+3]
        if chunk in alphabet:
            warnings.append({
                'category': 'Sequential Pattern',
                'severity': 'high',
                'message': f"Sequential alphabetical pattern detected ('{chunk}'). Predictable alphabetical runs are trivial to decipher."
            })
            break
        elif chunk in rev_alphabet:
            warnings.append({
                'category': 'Sequential Pattern',
                'severity': 'high',
                'message': f"Reverse alphabetical pattern detected ('{chunk}')."
            })
            break

    return warnings


def detect_keyboard_patterns(password: str) -> list[dict]:
    """Detect QWERTY horizontal runs, keypad runs, and diagonal patterns."""
    warnings = []
    lower_pwd = password.lower()

    for row in KEYBOARD_ROWS:
        for i in range(len(lower_pwd) - 3):
            sub = lower_pwd[i:i+4]
            if sub in row:
                warnings.append({
                    'category': 'Keyboard Pattern',
                    'severity': 'high',
                    'message': f"Keyboard spatial walk detected ('{sub}'). Keyboard-adjacent combinations are tested early in dictionary attacks."
                })
                return warnings

    for diag in KEYBOARD_DIAGONALS:
        for i in range(len(lower_pwd) - 2):
            sub = lower_pwd[i:i+3]
            if sub in diag:
                warnings.append({
                    'category': 'Keyboard Pattern',
                    'severity': 'medium',
                    'message': f"Diagonal keyboard pattern detected ('{sub}')."
                })
                return warnings

    return warnings


def detect_dictionary_words(password: str) -> list[dict]:
    """Detect natural English words and leetspeak variants."""
    warnings = []
    lower_pwd = password.lower()
    normalized = normalize_leetspeak(password)

    for word in DICTIONARY_WORDS:
        if len(word) >= 4:
            if word in lower_pwd:
                warnings.append({
                    'category': 'Dictionary Word',
                    'severity': 'medium',
                    'message': f"Recognized dictionary word detected: '{word}'. Standard dictionary attacks target this pattern."
                })
                break
            elif word in normalized and word not in lower_pwd:
                warnings.append({
                    'category': 'Dictionary Word',
                    'severity': 'medium',
                    'message': f"Obfuscated dictionary word detected via leetspeak translation ('{word}')."
                })
                break

    return warnings


# -------------------------------------------------------------------------
# Cryptographic Entropy & Cracking Metrics
# -------------------------------------------------------------------------

def calculate_entropy_metrics(password: str) -> dict:
    """
    Computes Shannon Entropy: H = L * log2(R)
    Determines cracking difficulty rating and attack resistance.
    """
    if not password:
        return {
            'bits': 0.0,
            'pool_size': 0,
            'difficulty_rating': 'None',
            'difficulty_badge': 'badge-trivial',
            'difficulty_desc': 'Awaiting input to calculate cryptographic entropy.',
            'combinations_display': '0',
            'combinations_raw': 0
        }

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    pool_size = (26 if has_lower else 0) + \
                (26 if has_upper else 0) + \
                (10 if has_digit else 0) + \
                (33 if has_symbol else 0)

    if pool_size == 0 or length == 0:
        return {
            'bits': 0.0,
            'pool_size': 0,
            'difficulty_rating': 'None',
            'difficulty_badge': 'badge-trivial',
            'difficulty_desc': 'Awaiting input.',
            'combinations_display': '0',
            'combinations_raw': 0
        }

    entropy_bits = round(length * math.log2(pool_size), 1)
    combinations = math.pow(pool_size, length)

    # Human-readable combinations format
    if combinations < 1000:
        comb_str = f"{int(combinations):,}"
    elif combinations < 1_000_000_000:
        comb_str = f"{combinations:,.0f}"
    else:
        comb_str = f"{combinations:.2e}".replace('e+', ' × 10^')

    # Cracking difficulty tiers & descriptions
    if entropy_bits < 28:
        difficulty_rating = 'Trivial'
        difficulty_badge = 'badge-trivial'
        difficulty_desc = 'Extremely weak. Vulnerable to instantaneous brute-force cracking within milliseconds.'
    elif entropy_bits < 36:
        difficulty_rating = 'Very Low'
        difficulty_badge = 'badge-low'
        difficulty_desc = 'Low entropy. Trivial to breach with commodity hardware using basic wordlists.'
    elif entropy_bits < 60:
        difficulty_rating = 'Moderate'
        difficulty_badge = 'badge-moderate'
        difficulty_desc = 'Reasonable complexity for low-value accounts; vulnerable to dedicated GPU rigs.'
    elif entropy_bits < 80:
        difficulty_rating = 'Strong'
        difficulty_badge = 'badge-strong'
        difficulty_desc = 'High entropy. Highly resistant against standard offline and online attack vectors.'
    else:
        difficulty_rating = 'Military Grade'
        difficulty_badge = 'badge-extreme'
        difficulty_desc = 'Optimal cryptographic resilience. Practically uncrackable under current computing constraints.'

    return {
        'bits': entropy_bits,
        'pool_size': pool_size,
        'difficulty_rating': difficulty_rating,
        'difficulty_badge': difficulty_badge,
        'difficulty_desc': difficulty_desc,
        'combinations_display': comb_str,
        'combinations_raw': combinations
    }


def format_duration(seconds: float) -> str:
    """Formats cracking duration into intuitive, professional human units."""
    if seconds < 0.001:
        return "Instant (< 1 ms)"
    elif seconds < 1:
        return f"{int(seconds * 1000)} milliseconds"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        mins = round(seconds / 60, 1)
        return f"{mins} minutes"
    elif seconds < 86400:
        hours = round(seconds / 3600, 1)
        return f"{hours} hours"
    elif seconds < 31536000:
        days = round(seconds / 86400, 1)
        return f"{days} days"
    elif seconds < 31536000 * 100:
        years = int(seconds / 31536000)
        return f"{years:,} years"
    elif seconds < 31536000 * 1000000:
        centuries = int(seconds / (31536000 * 100))
        return f"{centuries:,} centuries"
    else:
        return "Millions of years (Uncrackable)"


def estimate_brute_force_scenarios(password: str) -> dict:
    """
    Computes crack times across 4 realistic threat scenarios:
    1. High-End GPU Cluster (100 Billion guesses/sec - e.g. Hashcat on 100x RTX 4090)
    2. Single Modern GPU (1 Billion guesses/sec - RTX 4090 / 3090)
    3. Fast Online Attack (1,000 requests/sec - unthrottled API endpoint)
    4. Throttled Online Attack (10 requests/sec - rate-limited web login with Captcha)
    """
    if not password:
        return {
            'gpu_cluster': {'time': 'Instant', 'rate': '100 Billion/s', 'seconds': 0},
            'single_gpu': {'time': 'Instant', 'rate': '1 Billion/s', 'seconds': 0},
            'online_fast': {'time': 'Instant', 'rate': '1,000 req/s', 'seconds': 0},
            'online_throttled': {'time': 'Instant', 'rate': '10 req/s', 'seconds': 0}
        }

    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool += 33

    combinations = math.pow(pool, len(password)) if pool > 0 else 0
    # Average 50% search space coverage
    avg_guesses = combinations / 2.0

    cluster_rate = 100_000_000_000  # 100B / sec
    gpu_rate = 1_000_000_000        # 1B / sec
    online_fast_rate = 1_000        # 1k / sec
    online_throttled_rate = 10      # 10 / sec

    cluster_sec = avg_guesses / cluster_rate if cluster_rate > 0 else 0
    gpu_sec = avg_guesses / gpu_rate if gpu_rate > 0 else 0
    online_fast_sec = avg_guesses / online_fast_rate if online_fast_rate > 0 else 0
    online_throttled_sec = avg_guesses / online_throttled_rate if online_throttled_rate > 0 else 0

    return {
        'gpu_cluster': {
            'title': 'High-End GPU Cluster',
            'rate': '100 Billion/sec (Hashcat / Multi-RTX 4090)',
            'time': format_duration(cluster_sec),
            'seconds': cluster_sec
        },
        'single_gpu': {
            'title': 'Single Modern GPU',
            'rate': '1 Billion/sec (Single RTX 4090)',
            'time': format_duration(gpu_sec),
            'seconds': gpu_sec
        },
        'online_fast': {
            'title': 'Unthrottled Online Attack',
            'rate': '1,000 req/sec (Unprotected API)',
            'time': format_duration(online_fast_sec),
            'seconds': online_fast_sec
        },
        'online_throttled': {
            'title': 'Rate-Limited Web Login',
            'rate': '10 req/sec (Captcha / Lockout Protected)',
            'time': format_duration(online_throttled_sec),
            'seconds': online_throttled_sec
        }
    }


# -------------------------------------------------------------------------
# Master Analysis Function
# -------------------------------------------------------------------------

def analyze_password(password: str, is_known_breached: bool = False) -> dict:
    """
    Evaluates password strength with:
    - Entropy in bits ($H = L * log2(R)$)
    - Estimated cracking difficulty rating & description
    - Estimated brute-force attack time across multiple realistic threat scenarios
    - Common passwords, repeated characters, sequential patterns, keyboard runs, dictionary words
    - Normalized score (0-100) and status
    """
    if not password:
        entropy_data = calculate_entropy_metrics('')
        scenarios = estimate_brute_force_scenarios('')
        return {
            'score': 0,
            'status': 'Weak',
            'entropy': 0.0,
            'entropy_metrics': entropy_data,
            'attack_scenarios': scenarios,
            'length': 0,
            'pool_size': 0,
            'crack_time': {'offline_fast': 'Instant', 'online_throttled': 'Instant', 'offline_seconds': 0},
            'criteria': {
                'length_8': False,
                'length_12': False,
                'has_upper': False,
                'has_lower': False,
                'has_digit': False,
                'has_symbol': False,
                'no_patterns': True,
                'not_breached': True
            },
            'warnings': [],
            'penalties': [],
            'suggestions': ["Enter a password to initiate cryptographic diagnostics."]
        }

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    pool_size = (26 if has_lower else 0) + \
                (26 if has_upper else 0) + \
                (10 if has_digit else 0) + \
                (33 if has_symbol else 0)

    # 1. Structural Scoring
    score = 0
    suggestions = []
    is_under_eight = length < 8

    if is_under_eight:
        score += min(20, length * 2.5)
        suggestions.append("Length must be at least 8 characters (12-16+ recommended).")
    else:
        score += 20
        if length >= 12: score += 15
        if length >= 16: score += 10

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    if has_upper: score += 15
    else: suggestions.append("Add uppercase letters (A-Z).")
    if has_lower: score += 15
    else: suggestions.append("Add lowercase letters (a-z).")
    if has_digit: score += 15
    else: suggestions.append("Include numerical digits (0-9).")
    if has_symbol: score += 15
    else: suggestions.append("Include special symbols (!, @, #, $, %, etc.).")

    if variety == 4 and length >= 10:
        score += 10

    # 2. Pattern and Vulnerability Checks
    all_warnings = []
    all_warnings.extend(detect_common_password(password, is_known_breached))
    all_warnings.extend(detect_repeated_characters(password))
    all_warnings.extend(detect_sequential_patterns(password))
    all_warnings.extend(detect_keyboard_patterns(password))
    all_warnings.extend(detect_dictionary_words(password))

    has_critical = any(w['severity'] == 'critical' for w in all_warnings)
    for w in all_warnings:
        if w['severity'] == 'critical': score -= 50
        elif w['severity'] == 'high': score -= 18
        elif w['severity'] == 'medium': score -= 10

    if variety == 1:
        score -= 20
        suggestions.append("Avoid relying on a single character class.")

    if is_under_eight: score = min(25, score)
    if has_critical: score = min(15, score)

    final_score = max(0, min(100, round(score)))

    # Determine Status
    if is_under_eight or has_critical or final_score <= 25:
        status = 'Weak'
    elif final_score <= 55:
        status = 'Medium'
    elif final_score <= 80:
        status = 'Strong'
    else:
        status = 'Very Strong'

    entropy_data = calculate_entropy_metrics(password)
    scenarios = estimate_brute_force_scenarios(password)

    if not suggestions and final_score >= 80:
        suggestions.append("Optimal entropy! Excellent protection against modern cracking rigs.")

    return {
        'score': final_score,
        'status': status,
        'entropy': entropy_data['bits'],
        'entropy_metrics': entropy_data,
        'attack_scenarios': scenarios,
        'length': length,
        'pool_size': pool_size,
        'crack_time': {
            'offline_fast': scenarios['gpu_cluster']['time'],
            'single_gpu': scenarios['single_gpu']['time'],
            'online_throttled': scenarios['online_throttled']['time'],
            'offline_seconds': scenarios['gpu_cluster']['seconds']
        },
        'criteria': {
            'length_8': length >= 8,
            'length_12': length >= 12,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_digit': has_digit,
            'has_symbol': has_symbol,
            'no_patterns': len(all_warnings) == 0,
            'not_breached': not has_critical
        },
        'warnings': all_warnings,
        'penalties': [w['message'] for w in all_warnings],
        'suggestions': suggestions
    }
