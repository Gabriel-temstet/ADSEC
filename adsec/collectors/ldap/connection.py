"""Construction de connexions LDAP.

`build_connection` cree une connexion reelle vers un controleur de domaine.
Les tests injectent une fabrique alternative (voir `tests/fixtures`) basee
sur la strategie `MOCK_SYNC` de ldap3, qui simule un serveur LDAP en
memoire sans necessiter d'AD reel.
"""

from __future__ import annotations

from collections.abc import Callable

from ldap3 import ALL, SIMPLE, Connection, Server

from adsec.core.models.enums import CredentialType
from adsec.credentials.provider import Credential

ConnectionFactory = Callable[[str, Credential, int, bool], Connection]


def build_connection(
    target: str, credential: Credential, port: int = 389, use_ssl: bool = False
) -> Connection:
    """Construit une connexion ldap3 reelle vers `target`.

    La connexion n'est PAS liee (bind) automatiquement : l'appelant decide
    du moment du bind pour pouvoir tracer l'operation dans l'audit log.
    """
    server = Server(target, port=port, use_ssl=use_ssl, get_info=ALL)
    if credential.credential_type == CredentialType.USER and credential.principal:
        return Connection(
            server,
            user=credential.principal,
            password=credential.secret,
            authentication=SIMPLE,
            auto_bind=False,
        )
    return Connection(server, auto_bind=False)
