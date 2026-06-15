# constants.py

# Allowed strong algorithms
ALLOWED_ALGORITHMS = [
    "HS256",
    "RS256",
    "ES256"
]

# Weak / deprecated algorithms
WEAK_ALGORITHMS = [
    "none",
    "HS1",
    "HS128",
    "SHA1",
    "RS1",
    "MD5"
]

# Rare / uncommon algorithms
RARE_ALGORITHMS = [
    "ES384",
    "ES512",
    "RS384",
    "RS512"
]

# Recommended JWT claims
RECOMMENDED_CLAIMS = [
    "exp",
    "iat",
    "sub"
]

# Sensitive keywords that should not appear in payload
SENSITIVE_KEYWORDS = [
    "password",
    "secret",
    "api_key",
    "token",
    "credit",
    "card",
    "ssn",
    "private",
    "auth",
    "key"
]

# Maximum recommended lifetime (24 hours)
DEFAULT_MAX_EXPIRATION_SECONDS = 86400
