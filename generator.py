import secrets
import string

def generate_secure_password(
    length: int = 16,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = True
) -> str:
    """
    Generates a cryptographically strong random password using Python's secrets module.
    """
    length = max(4, min(128, length))

    char_pool = ""
    guaranteed = []

    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    symbol_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if exclude_ambiguous:
        # Exclude confusing lookalikes: 0, O, o, 1, l, I
        ambiguous = "0Oo1lI|`'\"~"
        upper_chars = "".join(c for c in upper_chars if c not in ambiguous)
        lower_chars = "".join(c for c in lower_chars if c not in ambiguous)
        digit_chars = "".join(c for c in digit_chars if c not in ambiguous)
        symbol_chars = "".join(c for c in symbol_chars if c not in ambiguous)

    if include_upper:
        char_pool += upper_chars
        guaranteed.append(secrets.choice(upper_chars))
    if include_lower:
        char_pool += lower_chars
        guaranteed.append(secrets.choice(lower_chars))
    if include_digits:
        char_pool += digit_chars
        guaranteed.append(secrets.choice(digit_chars))
    if include_symbols:
        char_pool += symbol_chars
        guaranteed.append(secrets.choice(symbol_chars))

    if not char_pool:
        # Fallback to alphanumeric
        char_pool = string.ascii_letters + string.digits
        guaranteed.append(secrets.choice(char_pool))

    remaining_length = length - len(guaranteed)
    if remaining_length > 0:
        guaranteed.extend(secrets.choice(char_pool) for _ in range(remaining_length))

    # Shuffle using cryptographic random
    rng = secrets.SystemRandom()
    rng.shuffle(guaranteed)

    return "".join(guaranteed)
