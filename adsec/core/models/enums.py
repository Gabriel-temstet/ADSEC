"""Enumerations partagees par l'ensemble du moteur ADSEC."""

from __future__ import annotations

from enum import Enum


class AccessLevel(str, Enum):
    """Niveau d'acces reel obtenu sur l'environnement audite."""

    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    AUDITOR = "auditor"
    PRIVILEGED = "privileged"


class ScanProfile(str, Enum):
    """Profil de scan definissant l'intensite de la collecte/des controles."""

    PASSIVE = "passive"
    SAFE = "safe"
    STANDARD = "standard"
    DEEP = "deep"


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ScanJobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScopeEntryType(str, Enum):
    DOMAIN = "domain"
    HOST_INCLUDE = "host_include"
    HOST_EXCLUDE = "host_exclude"
    NETWORK_INCLUDE = "network_include"
    NETWORK_EXCLUDE = "network_exclude"


class CredentialType(str, Enum):
    ANONYMOUS = "anonymous"
    USER = "user"
    KERBEROS_TICKET = "kerberos_ticket"
    EXTERNAL_SECRET = "external_secret"  # nosec B105 - nom de type, pas un secret


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"


class RelationConfidence(str, Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFERRED = "inferred"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
