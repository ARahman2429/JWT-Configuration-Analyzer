# agent.py

from utils import decode_jwt, JWTDecodeError
from analyzer import (
    check_signature_structure,
    check_algorithm,
    check_expiration,
    check_claims,
    check_nbf,
    check_sensitive_data,
    classify_algorithm   
)


class JWTConfigCheckAgent:

    def analyze(self, token):

        report = {
            "agent": "JWTConfigCheck",
            "token_summary": {},
            "issues": []
        }

        try:

            header, payload, signature = decode_jwt(token)

            alg = header.get("alg")

            report["token_summary"]["algorithm"] = alg
            report["token_summary"]["algorithm_strength"] = classify_algorithm(alg)
            report["token_summary"]["claims"] = list(payload.keys())

            issues = []

            issues.extend(check_signature_structure(token))
            issues.extend(check_algorithm(header))
            issues.extend(check_expiration(payload))
            issues.extend(check_claims(payload))
            issues.extend(check_nbf(payload))
            issues.extend(check_sensitive_data(payload))

            if not issues:
                issues.append({
                    "severity": "INFO",
                    "title": "No issues detected",
                    "description": "JWT appears properly configured",
                    "evidence": "No misconfiguration found",
                    "recommendation": "None"
                })

            report["issues"] = issues

        except JWTDecodeError as e:

            report["issues"].append({
                "severity": "CRITICAL",
                "title": "JWT decode error",
                "description": "Failed to decode JWT",
                "evidence": str(e),
                "recommendation": "Check token format"
            })

        return report