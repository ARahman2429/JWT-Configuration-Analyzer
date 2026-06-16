# analyzer.py

from datetime import datetime, timezone
from constants import (
    ALLOWED_ALGORITHMS,
    WEAK_ALGORITHMS,
    RARE_ALGORITHMS,
    RECOMMENDED_CLAIMS,
    SENSITIVE_KEYWORDS,
    DEFAULT_MAX_EXPIRATION_SECONDS
)


def check_signature_structure(token):

    issues = []

    parts = token.split(".")

    if len(parts) != 3:
        issues.append({
            "severity": "CRITICAL",
            "title": "Malformed JWT",
            "description": "JWT must contain header.payload.signature",
            "evidence": f"Segments detected: {len(parts)}",
            "recommendation": "Ensure correct JWT format"
        })
        return issues

    signature = parts[2]

    if signature == "":
        issues.append({
            "severity": "CRITICAL",
            "title": "Missing signature",
            "description": "JWT signature part is empty",
            "evidence": "Signature segment empty",
            "recommendation": "Ensure token is signed"
        })

    return issues


def check_algorithm(header):

    issues = []
    alg = header.get("alg")

    if not alg:
        issues.append({
            "severity": "HIGH",
            "title": "Missing alg claim",
            "description": "JWT header missing algorithm",
            "evidence": "alg not present",
            "recommendation": "Specify secure algorithm"
        })
        return issues

    if alg.lower() == "none":
        issues.append({
            "severity": "CRITICAL",
            "title": "None algorithm allowed",
            "description": "Unsigned tokens allow forgery",
            "evidence": "alg=none",
            "recommendation": "Disable none algorithm"
        })

    elif alg in WEAK_ALGORITHMS:
        issues.append({
            "severity": "HIGH",
            "title": "Weak signing algorithm",
            "description": "Deprecated signing algorithm used",
            "evidence": f"alg={alg}",
            "recommendation": "Use HS256 or RS256"
        })

    elif alg in RARE_ALGORITHMS:
        issues.append({
            "severity": "INFO",
            "title": "Rare algorithm detected",
            "description": "Algorithm rarely used",
            "evidence": f"alg={alg}",
            "recommendation": "Ensure this is intentional"
        })

    elif alg not in ALLOWED_ALGORITHMS:
        issues.append({
            "severity": "MEDIUM",
            "title": "Unapproved algorithm",
            "description": "Algorithm not in allowed list",
            "evidence": f"alg={alg}",
            "recommendation": "Use approved algorithms"
        })

    return issues


def check_expiration(payload):

    issues = []

    exp = payload.get("exp")

    if not exp:
        issues.append({
            "severity": "HIGH",
            "title": "Missing exp claim",
            "description": "Token has no expiration",
            "evidence": "exp missing",
            "recommendation": "Add expiration claim"
        })
        return issues

    current = datetime.now(timezone.utc).timestamp()

    lifetime = exp - current

    if lifetime > DEFAULT_MAX_EXPIRATION_SECONDS:
        issues.append({
            "severity": "MEDIUM",
            "title": "Excessive expiration",
            "description": "Token valid for too long",
            "evidence": f"Lifetime seconds: {int(lifetime)}",
            "recommendation": "Reduce token lifetime"
        })

    if lifetime < 0:
        issues.append({
            "severity": "INFO",
            "title": "Token expired",
            "description": "Token already expired",
            "evidence": f"exp={exp}",
            "recommendation": "Ensure token refresh"
        })

    return issues


def check_nbf(payload):

    issues = []

    nbf = payload.get("nbf")

    if nbf:

        current = datetime.now(timezone.utc).timestamp()

        if current < nbf:
            issues.append({
                "severity": "LOW",
                "title": "Token not yet valid",
                "description": "nbf indicates token not valid yet",
                "evidence": f"nbf={nbf}",
                "recommendation": "Check token issuance"
            })

    return issues


def check_claims(payload):

    issues = []

    for claim in RECOMMENDED_CLAIMS:

        if claim not in payload:
            issues.append({
                "severity": "LOW",
                "title": f"Missing claim {claim}",
                "description": f"{claim} recommended but missing",
                "evidence": f"{claim} not present",
                "recommendation": f"Include {claim}"
            })

    return issues


def check_sensitive_data(payload):

    issues = []

    def scan_object(obj, path=""):

        if isinstance(obj, dict):

            for key, value in obj.items():

                key_lower = key.lower()

                for keyword in SENSITIVE_KEYWORDS:

                    if keyword in key_lower:

                        issues.append({
                            "severity": "HIGH",
                            "title": "Sensitive data in JWT payload",
                            "description": "JWT payload contains sensitive information",
                            "evidence": f"Field detected: {path + key}",
                            "recommendation": "Do not store sensitive data inside JWT payload"
                        })

                scan_object(value, path + key + ".")

        elif isinstance(obj, list):

            for index, item in enumerate(obj):
                scan_object(item, path + f"[{index}].")

    scan_object(payload)

    return issues

def classify_algorithm(alg: str):

    if not alg:
        return "Algorithm could not be determined"

    if alg.lower() == "none":
        return "It is a weak algorithm (no signature)"

    if alg in WEAK_ALGORITHMS:
        return f"It is a weak algorithm ({alg})"

    if alg in RARE_ALGORITHMS:
        return f"It is a rare algorithm ({alg})"

    if alg in ALLOWED_ALGORITHMS:
        return f"It is a strong algorithm ({alg})"

    return f"Algorithm {alg} is not recognized and may be unsafe"