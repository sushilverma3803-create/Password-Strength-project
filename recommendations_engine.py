from typing import List, Dict, Any

class SecurityRecommendationsEngine:
    """
    Heuristic rule-based cybersecurity recommendations engine.
    Analyzes password characteristics, entropy, attack metrics, and vulnerabilities
    to deliver prioritized, actionable hardening recommendations.
    """

    @classmethod
    def generate_recommendations(
        cls,
        password: str,
        score: int,
        entropy: float,
        criteria: Dict[str, bool],
        warnings: List[Dict[str, str]],
        is_breached: bool,
        breach_count: int = 0
    ) -> List[Dict[str, Any]]:
        recs = []

        if not password:
            return [{
                'id': 'REC_AWAIT',
                'severity': 'INFO',
                'badge_class': 'badge-info',
                'title': 'Cryptographic Engine Idle',
                'message': 'Type or generate a password to receive customized threat mitigation and hardening advice.',
                'action': 'Begin typing or click Generate Strong Password.'
            }]

        length = len(password)

        # 1. Critical: Breach Exposure
        if is_breached:
            count_str = f"{breach_count:,}" if breach_count > 0 else "multiple"
            recs.append({
                'id': 'CRIT_BREACHED',
                'severity': 'CRITICAL',
                'badge_class': 'badge-danger',
                'icon': 'threat',
                'title': 'Immediate Compromise Alert',
                'message': f'This password has appeared in {count_str} known data breach dumps. Automated credential-stuffing bots will crack this instantly.',
                'action': 'Discard this password immediately. Never reuse compromised passwords across services.'
            })

        # 2. Critical/Warning: Length Analysis
        if length < 8:
            recs.append({
                'id': 'CRIT_LENGTH_VERY_SHORT',
                'severity': 'CRITICAL',
                'badge_class': 'badge-danger',
                'icon': 'ruler',
                'title': 'Critically Short Character Length',
                'message': f'At only {length} characters, modern brute-force hardware searches the entire combination space in seconds.',
                'action': 'Increase password length to a minimum of 12 characters, or preferably 16+ characters.'
            })
        elif length < 12:
            recs.append({
                'id': 'WARN_LENGTH_SHORT',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'ruler',
                'title': 'Sub-Optimal Password Length',
                'message': f'Length is {length} characters. Industry standards (NIST SP 800-63B) recommend at least 12–16 characters.',
                'action': 'Extend length with 4+ additional random characters or convert into a memorable multi-word passphrase.'
            })
        elif length >= 16 and score >= 80:
            recs.append({
                'id': 'OPT_LENGTH_EXCELLENT',
                'severity': 'OPTIMAL',
                'badge_class': 'badge-success',
                'icon': 'shield',
                'title': 'Exceptional Length Defense',
                'message': f'16+ characters ({length} chars) creates an astronomical search space resilient against billion-hash/second attacks.',
                'action': 'Maintain this length profile across all mission-critical accounts.'
            })

        # 3. Character Diversity Recommendations
        missing_classes = []
        if not criteria.get('has_upper', False): missing_classes.append('Uppercase letters (A-Z)')
        if not criteria.get('has_lower', False): missing_classes.append('Lowercase letters (a-z)')
        if not criteria.get('has_digit', False): missing_classes.append('Numerical digits (0-9)')
        if not criteria.get('has_symbol', False): missing_classes.append('Special symbols (!@#$%^&*)')

        if len(missing_classes) >= 3:
            recs.append({
                'id': 'CRIT_CHARSET_LIMITED',
                'severity': 'CRITICAL',
                'badge_class': 'badge-danger',
                'icon': 'key',
                'title': 'Extremely Restricted Character Pool',
                'message': f'Missing: {", ".join(missing_classes)}. A restricted pool enables fast dictionary and mask attacks.',
                'action': 'Incorporate mixed cases, numbers, and special symbols to dramatically expand character pool search space.'
            })
        elif len(missing_classes) > 0:
            recs.append({
                'id': 'WARN_CHARSET_MISSING',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'key',
                'title': 'Diversify Character Classes',
                'message': f'Consider adding: {", ".join(missing_classes)} to raise character pool from 26/52 to 94 possible characters.',
                'action': f'Inject at least one {missing_classes[0]} in the middle of your password.'
            })

        # 4. Pattern & Structure Warnings
        has_repeats = any(w.get('category') == 'Repeated Characters' for w in warnings)
        has_sequence = any(w.get('category') == 'Sequential Pattern' for w in warnings)
        has_keyboard = any(w.get('category') == 'Keyboard Pattern' for w in warnings)
        has_dict = any(w.get('category') == 'Dictionary Word' for w in warnings)

        if has_repeats:
            recs.append({
                'id': 'WARN_REPEATED_CHARS',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'alert',
                'title': 'Repetitive Character Sequences Detected',
                'message': 'Consecutive identical characters add virtually zero cryptographic entropy and are prioritized by crackers.',
                'action': 'Eliminate character streaks (e.g., replace "aaaa" or "111" with distinct entropy characters).'
            })

        if has_sequence:
            recs.append({
                'id': 'WARN_SEQUENTIAL_CHARS',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'alert',
                'title': 'Predictable Sequential Sequences',
                'message': 'Alphabetical or numerical series (like "1234", "abcd") are explicitly checked by rule-based cracking engines.',
                'action': 'Break continuous chains with non-linear symbols or randomized numbers.'
            })

        if has_keyboard:
            recs.append({
                'id': 'WARN_KEYBOARD_WALK',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'alert',
                'title': 'Keyboard Spatial Pattern Detected',
                'message': 'Spatial walks (such as "qwerty", "asdfgh") are among the first candidate lists loaded into John the Ripper and Hashcat.',
                'action': 'Avoid adjacent keystrokes along rows or columns.'
            })

        if has_dict:
            recs.append({
                'id': 'WARN_DICTIONARY_WORD',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'book',
                'title': 'Dictionary Words Found',
                'message': 'Recognizable dictionary words leave passwords vulnerable to hybrid wordlist + leetspeak permutation attacks.',
                'action': 'Replace full root words or interleave non-standard symbols and mixed case throughout.'
            })

        # 5. Shannon Entropy Assessment
        if entropy < 36 and not any(r['id'].startswith('CRIT') for r in recs):
            recs.append({
                'id': 'WARN_LOW_ENTROPY',
                'severity': 'WARNING',
                'badge_class': 'badge-warning',
                'icon': 'cpu',
                'title': 'Insufficient Shannon Entropy',
                'message': f'Entropy is only {round(entropy, 1)} bits. High-security enterprise systems mandate at least 60+ bits.',
                'action': 'Target at least 64 bits of entropy to guarantee computational infeasibility.'
            })
        elif entropy >= 72:
            recs.append({
                'id': 'OPT_MILITARY_ENTROPY',
                'severity': 'OPTIMAL',
                'badge_class': 'badge-success',
                'icon': 'check',
                'title': 'High-Grade Cryptographic Entropy',
                'message': f'Outstanding entropy metric of {round(entropy, 1)} bits. Offline brute force would require millions of computing years.',
                'action': 'Use an encrypted password manager or your CyberGuard Vault to store this credential.'
            })

        # 6. Passphrase Suggestion if moderate
        if score < 75 and length < 16:
            recs.append({
                'id': 'INFO_PASSPHRASE_TIP',
                'severity': 'RECOMMENDED',
                'badge_class': 'badge-info',
                'icon': 'lightbulb',
                'title': 'Pro-Tip: Passphrase Architecture',
                'message': 'Four random unrelated dictionary words (e.g. "correct-horse-battery-staple") generate over 75+ bits of entropy and are easy to recall.',
                'action': 'Try combining 3–4 distinct words separated by special characters.'
            })

        # Sort recommendations: CRITICAL -> WARNING -> RECOMMENDED -> OPTIMAL -> INFO
        severity_rank = {'CRITICAL': 0, 'WARNING': 1, 'RECOMMENDED': 2, 'OPTIMAL': 3, 'INFO': 4}
        recs.sort(key=lambda x: severity_rank.get(x.get('severity', 'INFO'), 5))

        return recs
