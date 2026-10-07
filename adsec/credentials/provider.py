"""Abstraction des sources d'authentification.

Le moteur ne manipule jamais de secret en clair au-dela de la duree de vie
du process courant : un `CredentialProvider` resout un `Credential` a la
demande, sans que celui-ci transite jamais par la base SQLite (voir
`CredentialsMetadata.secret_ref` dans `core/models/scan.py`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from adsec.core.models.enums import CredentialType


@dataclass(frozen=True)
class Credential:
    """Un credential resolu, garde en memoire uniquement le temps du scan."""

    credential_type: CredentialType
    principal: str | None = None
    secret: str | None = None  # ex: mot de passe - jamais serialise en base


class CredentialProvider(Protocol):
    def get(self, purpose: str) -> Credential: ...


class AnonymousCredentialProvider:
    """Fournit un credential anonyme (aucune authentification)."""

    def get(self, purpose: str) -> Credential:
        return Credential(credential_type=CredentialType.ANONYMOUS)


class EnvironmentCredentialProvider:
    """Lit le principal/secret depuis des variables d'environnement.

    Convention : `<PREFIX>_BIND_DN` et `<PREFIX>_BIND_PASSWORD`, ex.
    `ADSEC_LDAP_BIND_DN` / `ADSEC_LDAP_BIND_PASSWORD`.
    """

    def __init__(self, env_prefix: str = "ADSEC_LDAP") -> None:
        self._principal_var = f"{env_prefix}_BIND_DN"
        self._secret_var = f"{env_prefix}_BIND_PASSWORD"

    def get(self, purpose: str) -> Credential:
        principal = os.environ.get(self._principal_var)
        secret = os.environ.get(self._secret_var)
        if not principal or not secret:
            return Credential(credential_type=CredentialType.ANONYMOUS)
        return Credential(credential_type=CredentialType.USER, principal=principal, secret=secret)


class StaticCredentialProvider:
    """Fournit un credential fixe, utile pour les tests et l'usage
    programmatique (ne lit ni l'environnement ni l'entree standard)."""

    def __init__(self, credential: Credential) -> None:
        self._credential = credential

    def get(self, purpose: str) -> Credential:
        return self._credential
