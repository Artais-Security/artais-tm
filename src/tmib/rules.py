from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict

# Keep the model simple/serializable
@dataclass(frozen=True)
class ThreatRow:
    category: str  # STRIDE
    threat: str
    example: str
    impact: str
    mitigations: list[str]


@dataclass(frozen=True)
class Model:
    assumptions: list[str]
    assets: list[str]
    trust_boundaries: list[str]
    threats: list[ThreatRow]
    checklist: dict[str, list[str]]
    abuse_cases: list[str]


def build_model(ans) -> Model:
    # baseline assumptions
    assumptions = [
        "Security controls are applied consistently across environments.",
        "Secrets are managed outside source control.",
        "Logging is available for auth and sensitive actions.",
    ]

    assets = ["User accounts", "Application source code", "Configuration & secrets"]
    if ans.stores_pii:
        assets.append("PII dataset")
    if ans.data_sensitivity in ("confidential", "regulated"):
        assets.append("Sensitive business data")

    trust_boundaries = [
        "Client ↔ Application",
        "Application ↔ Identity provider (if applicable)",
        "Application ↔ Data store",
    ]
    if ans.cloud != "none/on-prem":
        trust_boundaries.append("Application ↔ Cloud control plane APIs")

    # threats (tailor lightly based on answers)
    threats: list[ThreatRow] = []

    # S - Spoofing
    threats.append(ThreatRow(
        category="S",
        threat="Account takeover / credential stuffing",
        example="Attacker reuses leaked passwords against login endpoints.",
        impact="Unauthorized access to accounts and data.",
        mitigations=[
            "MFA where possible",
            "Rate limiting + IP reputation",
            "Password hashing (Argon2/bcrypt) and strong password policy",
            "Login anomaly detection",
        ],
    ))

    if ans.auth in ("jwt", "oauth2/oidc", "api_key"):
        threats.append(ThreatRow(
            category="S",
            threat="Token/key theft and replay",
            example="Bearer token captured via logs, client storage, or intercepted traffic.",
            impact="Session hijack; impersonation.",
            mitigations=[
                "TLS everywhere; HSTS if web",
                "Do not log tokens/keys",
                "Short token lifetimes + rotation",
                "Bind tokens to audience/issuer and validate claims",
            ],
        ))

    # T - Tampering
    threats.append(ThreatRow(
        category="T",
        threat="Request tampering / parameter manipulation",
        example="User modifies request JSON to access another tenant’s resource.",
        impact="Integrity breach; unauthorized changes.",
        mitigations=[
            "Server-side authorization checks on every object",
            "Use allowlists and strict schema validation",
            "Use prepared statements/ORM to prevent injection",
        ],
    ))

    # R - Repudiation
    threats.append(ThreatRow(
        category="R",
        threat="Insufficient auditability of sensitive actions",
        example="Admin changes permissions but action is not logged.",
        impact="Hard to investigate incidents; compliance gaps.",
        mitigations=[
            "Structured audit logging for auth and sensitive actions",
            "Time sync (NTP) + immutable log storage",
            "Log correlation IDs",
        ],
    ))

    # I - Information Disclosure
    if ans.internet_facing:
        threats.append(ThreatRow(
            category="I",
            threat="Sensitive data exposure via misconfig or IDOR",
            example="Direct object reference allows download of other users’ files.",
            impact="PII leak; regulatory exposure.",
            mitigations=[
                "Object-level authorization (per-resource checks)",
                "Secure defaults (deny-by-default)",
                "Encrypt data at rest + in transit",
                "CSP and secure headers for web apps",
            ],
        ))

    # D - Denial of Service
    threats.append(ThreatRow(
        category="D",
        threat="Resource exhaustion (DoS)",
        example="High request volume causes CPU/memory exhaustion.",
        impact="Outage; degraded performance.",
        mitigations=[
            "Rate limiting + WAF/CDN (if applicable)",
            "Timeouts, circuit breakers, queueing",
            "Autoscaling and load testing",
        ],
    ))

    # E - Elevation of Privilege
    threats.append(ThreatRow(
        category="E",
        threat="Authorization bypass / privilege escalation",
        example="User accesses admin endpoints due to missing role checks.",
        impact="Full compromise of system capabilities.",
        mitigations=[
            "Centralized authorization middleware",
            "Least privilege roles; separate admin surface",
            "Security testing for access control (unit + integration)",
        ],
    ))

    # Checklist (grouped)
    checklist: Dict[str, List[str]] = {
        "Auth & Session": [
            "Use MFA for privileged accounts",
            "Enforce secure password storage (Argon2/bcrypt) if passwords exist",
            "Rotate secrets/tokens; set short lifetimes for bearer tokens",
        ],
        "Input & Data": [
            "Validate inputs with strict schemas",
            "Protect against injection (SQL/NoSQL/command) using safe APIs",
            "Encrypt sensitive data at rest; manage keys securely",
        ],
        "Infrastructure": [
            "TLS everywhere; disable weak ciphers",
            "Least-privilege IAM/service accounts",
            "Harden container/host baseline; patch regularly",
        ],
        "Logging & Monitoring": [
            "Audit log auth events + sensitive actions",
            "Alert on suspicious auth patterns and privilege changes",
            "Scrub secrets from logs",
        ],
        "SDLC": [
            "SAST/secret scanning in CI",
            "Dependency updates + vulnerability monitoring",
            "Security review checklist before release",
        ],
    }

    if ans.data_sensitivity == "regulated":
        checklist.setdefault("Compliance", []).extend([
            "Define data retention + deletion policy",
            "Access reviews and least privilege enforcement",
            "Breach response runbook and evidence retention",
        ])

    # Abuse cases (Given/When/Then)
    abuse_cases = [
        "Given a valid user, when they modify an object ID, then the API must deny access to other users’ resources.",
        "Given repeated failed logins, when thresholds are hit, then rate limiting and lockout/step-up auth should trigger.",
        "Given an attacker can call endpoints at high volume, when load increases, then service should degrade gracefully (timeouts/queues) rather than crash.",
    ]
    if ans.auth in ("jwt", "oauth2/oidc"):
        abuse_cases.append("Given a token with wrong issuer/audience, when presented, then the service must reject it and log the event (without logging the token).")

    return Model(
        assumptions=assumptions,
        assets=assets,
        trust_boundaries=trust_boundaries,
        threats=threats,
        checklist=checklist,
        abuse_cases=abuse_cases,
    )
