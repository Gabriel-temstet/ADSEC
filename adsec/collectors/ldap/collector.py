"""Collector LDAP : discovery (root DSE) et collecte (users/groups/
computers/OUs). Aucune ecriture, aucune modification de l'annuaire.

Le controle de scope (`ScopeManager.assert_in_scope`) est effectue avant
toute connexion, conformement a la regle de securite centrale du produit.

La decouverte du root DSE s'appuie sur `Server(get_info=...)`, peuple par
ldap3 lors du bind (recherche root DSE interne standard pour un serveur
reel, profil hors-ligne pour les connexions de test MOCK_SYNC) plutot que
sur une recherche explicite a base vide, qui n'est pas supportee par la
strategie MOCK_SYNC de ldap3.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar, Literal

from ldap3 import BASE, SUBTREE, Connection
from ldap3.protocol.microsoft import security_descriptor_control

from adsec.collectors.base import CollectionResult, DiscoveryResult
from adsec.collectors.ldap.attributes import (
    UAC_DONT_EXPIRE_PASSWD,
    UAC_DONT_REQ_PREAUTH,
    UAC_TRUSTED_FOR_DELEGATION,
    as_list,
    decode_sid,
    filetime_to_iso,
    guid_from_dn,
    is_account_enabled,
    naming_context_to_fqdn,
    rdn_and_parent,
    uac_has_flag,
)
from adsec.collectors.ldap.connection import ConnectionFactory, build_connection
from adsec.collectors.ldap.rights import decode_rights, resolve_right_guid
from adsec.collectors.ldap.sddl import Ace, parse_security_descriptor
from adsec.core.models.enums import AccessLevel
from adsec.core.scope.scope_manager import ScopeManager
from adsec.credentials.provider import CredentialProvider

# GUID standard de l'extension "Deny All Extended Rights" non utilise ici ;
# LDAP_SERVER_SD_FLAGS_OID = OWNER (1) | DACL (4)
_SD_FLAGS_OWNER_AND_DACL = 0x05

_TRUST_DIRECTIONS = {"0": "disabled", "1": "inbound", "2": "outbound", "3": "bidirectional"}
_TRUST_TYPES = {"1": "downlevel", "2": "uplevel", "3": "mit", "4": "dce"}
_TRUST_ATTR_FILTER_SIDS = 0x4
_TRUST_ATTR_FOREST_TRANSITIVE = 0x8
_TRUST_ATTR_WITHIN_FOREST = 0x20

_KERBEROS_ATTRS = [
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-SupportedEncryptionTypes",
]
_OU_ATTRS = ["ou", "distinguishedName", "gPLink"]
_USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "objectSid",
    "userPrincipalName",
    "userAccountControl",
    "adminCount",
    "lastLogonTimestamp",
    "pwdLastSet",
    "servicePrincipalName",
    *_KERBEROS_ATTRS,
]
_GROUP_ATTRS = ["sAMAccountName", "distinguishedName", "objectSid", "member"]
_COMPUTER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "objectSid",
    "dNSHostName",
    "operatingSystem",
    "userAccountControl",
    *_KERBEROS_ATTRS,
]
_SD_ATTR = "nTSecurityDescriptor"
_GPO_ATTRS = ["displayName", "gPCFileSysPath", "versionNumber", "flags"]
_TRUST_ATTRS = ["trustPartner", "trustDirection", "trustType", "trustAttributes"]


class LdapDiscoveryError(Exception):
    pass


class LdapCollector:
    """Collector LDAP conforme au contrat `Collector`."""

    id = "ldap"
    required_access_level: ClassVar[AccessLevel] = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["ldap"]

    def __init__(
        self,
        scope_manager: ScopeManager,
        credential_provider: CredentialProvider,
        port: int = 389,
        use_ssl: bool = False,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._scope = scope_manager
        self._credentials = credential_provider
        self._port = port
        self._use_ssl = use_ssl
        self._connection_factory = connection_factory or build_connection
        self._naming_context_cache: dict[str, str] = {}

    async def discover(self, target: str) -> DiscoveryResult:
        self._scope.assert_in_scope(target)
        return await asyncio.to_thread(self._discover_sync, target)

    async def collect(self, target: str) -> CollectionResult:
        self._scope.assert_in_scope(target)
        return await asyncio.to_thread(self._collect_sync, target)

    # -- internes (synchrones, executees dans un thread) ---------------

    def _open_connection(self, target: str) -> Connection:
        credential = self._credentials.get("ldap")
        return self._connection_factory(target, credential, self._port, self._use_ssl)

    def _discover_sync(self, target: str) -> DiscoveryResult:
        conn = self._open_connection(target)
        limitations: list[str] = []
        access_level = AccessLevel.ANONYMOUS
        try:
            bound = conn.bind()
            if not bound:
                limitations.append(f"Bind refuse par {target}: {conn.result}")
            elif conn.user:
                access_level = AccessLevel.AUTHENTICATED

            info = conn.server.info
            other = info.other if info is not None else None
            if not other:
                raise LdapDiscoveryError(
                    f"Impossible de recuperer les informations root DSE de {target!r}"
                )

            naming_context = _first(other.get("defaultNamingContext"))
            if not naming_context:
                raise LdapDiscoveryError(f"defaultNamingContext absent du root DSE de {target!r}")
            self._naming_context_cache[target] = naming_context

            facts: dict[str, object] = {
                "naming_context": naming_context,
                "domain_fqdn": naming_context_to_fqdn(naming_context),
                "dns_hostname": _first(other.get("dnsHostName")),
                "forest_functionality": _first(other.get("forestFunctionality")),
                "domain_functionality": _first(other.get("domainFunctionality")),
            }
            return DiscoveryResult(
                access_level_achieved=access_level,
                facts=facts,
                partial=bool(limitations),
                limitations=limitations,
            )
        finally:
            conn.unbind()

    def _collect_sync(self, target: str) -> CollectionResult:
        naming_context = self._naming_context_cache.get(target)
        conn = self._open_connection(target)
        limitations: list[str] = []
        errors: list[str] = []
        objects: dict[str, list[dict[str, object]]] = {
            "ous": [],
            "users": [],
            "groups": [],
            "computers": [],
            "acls": [],
            "trusts": [],
            "gpos": [],
            "domain_root": [],
        }
        try:
            if not conn.bind():
                errors.append(f"Bind refuse par {target}: {conn.result}")
                return CollectionResult(
                    objects=objects, partial=True, limitations=limitations, errors=errors
                )

            if naming_context is None:
                info = conn.server.info
                other = info.other if info is not None else None
                naming_context = _first(other.get("defaultNamingContext")) if other else None
                if naming_context is None:
                    errors.append(f"naming context introuvable pour {target!r}")
                    return CollectionResult(
                        objects=objects, partial=True, limitations=limitations, errors=errors
                    )
                self._naming_context_cache[target] = naming_context

            objects["ous"] = self._search_ous(conn, naming_context, limitations)
            objects["users"] = self._search_users(conn, naming_context, limitations)
            objects["groups"] = self._search_groups(conn, naming_context, limitations)
            objects["computers"] = self._search_computers(conn, naming_context, limitations)
            objects["acls"] = self._search_acls(conn, naming_context, limitations)
            objects["trusts"] = self._search_trusts(conn, naming_context, limitations)
            objects["gpos"] = self._search_gpos(conn, naming_context, limitations)
            objects["domain_root"] = self._search_domain_root(
                conn, naming_context, objects["acls"], limitations
            )

            return CollectionResult(
                objects=objects,
                partial=bool(limitations),
                limitations=limitations,
                errors=errors,
            )
        finally:
            conn.unbind()

    def _search_with_sd_control(
        self,
        conn: Connection,
        base: str,
        search_filter: str,
        attributes: list[str],
        scope: Literal["BASE", "LEVEL", "SUBTREE"] = SUBTREE,
    ) -> bool:
        """Recherche avec le controle LDAP_SERVER_SD_FLAGS (necessaire sur
        un AD reel pour obtenir `nTSecurityDescriptor`). Se rabat sur une
        recherche sans controle si le serveur/la strategie de connexion ne
        le supporte pas (ex: connexions de test)."""
        try:
            return bool(
                conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                    controls=security_descriptor_control(sdflags=_SD_FLAGS_OWNER_AND_DACL),
                )
            )
        except Exception:  # noqa: BLE001 - degradation gracieuse (mock/serveurs non conformes)
            return bool(
                conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                )
            )

    def _search_acls(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        object_type_by_class = (
            ("groupPolicyContainer", "gpo"),
            ("organizationalUnit", "ou"),
            ("computer", "computer"),
            ("group", "group"),
            ("user", "user"),
        )
        seen_dns: set[str] = set()

        for ldap_class, object_type in object_type_by_class:
            ok = self._search_with_sd_control(
                conn,
                naming_context,
                f"(objectClass={ldap_class})",
                ["distinguishedName", _SD_ATTR],
            )
            if not ok:
                limitations.append(f"Recherche ACL ({object_type}) incomplete: {conn.result}")
                continue
            for entry in conn.entries:
                dn = str(entry.entry_dn)
                if dn in seen_dns:
                    continue  # deja classe via un type plus specifique
                seen_dns.add(dn)

                raw_sd = _raw(entry, _SD_ATTR)
                sd = parse_security_descriptor(raw_sd)
                if sd is None:
                    continue

                permissions = _permission_rows(sd.aces)
                results.append(
                    {
                        "object_dn": dn,
                        "object_type": object_type,
                        "owner_sid": sd.owner_sid,
                        "permissions": permissions,
                    }
                )
        return results

    def _search_trusts(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        ok = conn.search(
            search_base=f"CN=System,{naming_context}",
            search_filter="(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=_TRUST_ATTRS,
        )
        if not ok:
            limitations.append(f"Recherche trusts incomplete ou absente: {conn.result}")
            return results
        for entry in conn.entries:
            attrs_value = _single_int(entry, "trustAttributes") or 0
            results.append(
                {
                    "trust_partner": _single(entry, "trustPartner") or "",
                    "direction": _TRUST_DIRECTIONS.get(
                        str(_single_int(entry, "trustDirection") or 0), "unknown"
                    ),
                    "trust_type": _TRUST_TYPES.get(
                        str(_single_int(entry, "trustType") or 0), "unknown"
                    ),
                    "transitive": bool(
                        attrs_value & _TRUST_ATTR_FOREST_TRANSITIVE
                        or attrs_value & _TRUST_ATTR_WITHIN_FOREST
                    ),
                    "sid_filtering": bool(attrs_value & _TRUST_ATTR_FILTER_SIDS),
                    "raw_attrs": {"trustAttributes": attrs_value},
                }
            )
        return results

    def _search_gpos(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        ok = conn.search(
            search_base=f"CN=Policies,CN=System,{naming_context}",
            search_filter="(objectClass=groupPolicyContainer)",
            search_scope=SUBTREE,
            attributes=_GPO_ATTRS,
        )
        if not ok:
            limitations.append(f"Recherche GPO incomplete ou absente: {conn.result}")
            return results
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            guid = guid_from_dn(dn)
            if guid is None:
                continue
            results.append(
                {
                    "guid": guid,
                    "dn": dn,
                    "display_name": _single(entry, "displayName") or guid,
                    "file_sys_path": _single(entry, "gPCFileSysPath"),
                    "version_number": _single_int(entry, "versionNumber") or 0,
                    "flags": _single_int(entry, "flags") or 0,
                }
            )
        return results

    def _search_domain_root(
        self,
        conn: Connection,
        naming_context: str,
        acl_rows: list[dict[str, object]],
        limitations: list[str],
    ) -> list[dict[str, object]]:
        """Lit la racine du domaine : liens de GPO et ACL (droits de
        replication notamment). L'ACL est ajoutee a `acl_rows`."""
        ok = self._search_with_sd_control(
            conn,
            naming_context,
            "(objectClass=*)",
            ["distinguishedName", "gPLink", _SD_ATTR],
            scope=BASE,
        )
        if not ok or not conn.entries:
            limitations.append(f"Lecture de la racine du domaine incomplete: {conn.result}")
            return []
        entry = conn.entries[0]
        sd = parse_security_descriptor(_raw(entry, _SD_ATTR))
        if sd is not None:
            acl_rows.append(
                {
                    "object_dn": naming_context,
                    "object_type": "domain",
                    "owner_sid": sd.owner_sid,
                    "permissions": _permission_rows(sd.aces),
                }
            )
        return [{"dn": naming_context, "gplinks": as_list(_raw(entry, "gPLink"))}]

    def _search_ous(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        ok = conn.search(
            search_base=naming_context,
            search_filter="(objectClass=organizationalUnit)",
            search_scope=SUBTREE,
            attributes=_OU_ATTRS,
        )
        if not ok:
            limitations.append(f"Recherche OU incomplete: {conn.result}")
            return results
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            name, parent = rdn_and_parent(dn)
            results.append(
                {
                    "dn": dn,
                    "name": _single(entry, "ou") or name,
                    "parent_dn": parent,
                    "gplinks": as_list(_raw(entry, "gPLink")),
                }
            )
        return results

    def _search_users(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        ok = conn.search(
            search_base=naming_context,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            search_scope=SUBTREE,
            attributes=_USER_ATTRS,
        )
        if not ok:
            limitations.append(f"Recherche users incomplete: {conn.result}")
            return results
        for entry in conn.entries:
            uac = _single_int(entry, "userAccountControl")
            results.append(
                {
                    "dn": str(entry.entry_dn),
                    "sam_account_name": _single(entry, "sAMAccountName") or "",
                    "sid": decode_sid(_raw(entry, "objectSid")),
                    "upn": _single(entry, "userPrincipalName"),
                    "enabled": is_account_enabled(uac),
                    "admin_count": bool(_single_int(entry, "adminCount") or 0),
                    "password_never_expires": uac_has_flag(uac, UAC_DONT_EXPIRE_PASSWD),
                    "pre_auth_not_required": uac_has_flag(uac, UAC_DONT_REQ_PREAUTH),
                    "last_logon": filetime_to_iso(_raw(entry, "lastLogonTimestamp")),
                    "pwd_last_set": filetime_to_iso(_raw(entry, "pwdLastSet")),
                    "spns": as_list(_raw(entry, "servicePrincipalName")),
                    "raw_attrs": _kerberos_raw_attrs(entry, uac),
                }
            )
        return results

    def _search_groups(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        ok = conn.search(
            search_base=naming_context,
            search_filter="(objectClass=group)",
            search_scope=SUBTREE,
            attributes=_GROUP_ATTRS,
        )
        if not ok:
            limitations.append(f"Recherche groups incomplete: {conn.result}")
            return results
        for entry in conn.entries:
            results.append(
                {
                    "dn": str(entry.entry_dn),
                    "sam_account_name": _single(entry, "sAMAccountName") or "",
                    "sid": decode_sid(_raw(entry, "objectSid")),
                    "members": as_list(_raw(entry, "member")),
                }
            )
        return results

    def _search_computers(
        self, conn: Connection, naming_context: str, limitations: list[str]
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        ok = conn.search(
            search_base=naming_context,
            search_filter="(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=_COMPUTER_ATTRS,
        )
        if not ok:
            limitations.append(f"Recherche computers incomplete: {conn.result}")
            return results
        for entry in conn.entries:
            uac = _single_int(entry, "userAccountControl")
            results.append(
                {
                    "dn": str(entry.entry_dn),
                    "sam_account_name": _single(entry, "sAMAccountName") or "",
                    "sid": decode_sid(_raw(entry, "objectSid")),
                    "dns_hostname": _single(entry, "dNSHostName"),
                    "operating_system": _single(entry, "operatingSystem"),
                    "enabled": is_account_enabled(uac),
                    "unconstrained_delegation": uac_has_flag(uac, UAC_TRUSTED_FOR_DELEGATION),
                    "raw_attrs": _kerberos_raw_attrs(entry, uac),
                }
            )
        return results


def _first(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _raw(entry: object, name: str) -> object:
    if name not in entry.entry_attributes:  # type: ignore[attr-defined]
        return None
    attr = entry[name]  # type: ignore[index]
    raw_values = attr.raw_values
    if not raw_values:
        return None
    if len(raw_values) == 1:
        return raw_values[0]
    return raw_values


def _single(entry: object, name: str) -> str | None:
    if name not in entry.entry_attributes:  # type: ignore[attr-defined]
        return None
    value = entry[name].value  # type: ignore[index]
    if value is None:
        return None
    return str(value)


def _single_int(entry: object, name: str) -> int | None:
    value = _single(entry, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _permission_rows(aces: list[Ace]) -> list[dict[str, object]]:
    return [
        {
            "trustee_sid": ace.trustee_sid,
            "ace_type": ace.ace_type,
            "rights_mask": ace.access_mask,
            "rights": decode_rights(ace.access_mask),
            "object_type_guid": ace.object_type_guid,
            "resolved_right_name": resolve_right_guid(ace.object_type_guid),
            "inherited": ace.inherited,
        }
        for ace in aces
    ]


def _kerberos_raw_attrs(entry: object, uac: int | None) -> dict[str, object]:
    """Attributs lies a Kerberos conserves dans `raw_attrs` : delegation
    contrainte, RBCD (trustees decodes depuis le descripteur), types de
    chiffrement supportes."""
    rbcd_sd = parse_security_descriptor(_raw(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity"))
    return {
        "userAccountControl": uac,
        "delegate_to": as_list(_raw(entry, "msDS-AllowedToDelegateTo")),
        "rbcd_trustees": (
            sorted({ace.trustee_sid for ace in rbcd_sd.aces if ace.ace_type.startswith("ALLOWED")})
            if rbcd_sd is not None
            else []
        ),
        "supported_encryption_types": _single_int(entry, "msDS-SupportedEncryptionTypes"),
    }
