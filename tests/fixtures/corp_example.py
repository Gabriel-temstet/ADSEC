"""Fixture `corp.example` : petit domaine AD fictif simule via la strategie
MOCK_SYNC de ldap3, sans dependance a un AD reel.

Contient volontairement des cas de test representatifs :
- un utilisateur avec adminCount=1 (compte a privileges) ;
- un utilisateur AS-REP roastable (pre-authentification desactivee) ;
- un utilisateur porteur d'un SPN (Kerberoastable) ;
- un groupe "Domain Admins" avec un membre imbrique via un autre groupe ;
- un ordinateur en delegation non contrainte (unconstrained delegation).
"""

from __future__ import annotations

from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, SIMPLE, Connection, Server

from adsec.collectors.ldap.rights import (
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_GENERIC_ALL,
    RIGHT_GENERIC_WRITE,
    RIGHT_WRITE_OWNER,
)
from adsec.credentials.provider import Credential
from tests.fixtures.sddl_builder import FakeAce, build_security_descriptor, encode_sid

NAMING_CONTEXT = "DC=corp,DC=example"
DC_HOSTNAME = "dc01.corp.example"

DOMAIN_SID = "S-1-5-21-1111-2222-3333"
SID_ALICE = f"{DOMAIN_SID}-1105"
SID_BOB = f"{DOMAIN_SID}-1106"
SID_SVC_SQL = f"{DOMAIN_SID}-1107"
SID_HELPDESK = f"{DOMAIN_SID}-1108"
SID_DOMAIN_ADMINS = f"{DOMAIN_SID}-512"
SID_AUTH_USERS = "S-1-5-11"
SID_SYSTEM = "S-1-5-18"
FORCE_CHANGE_PASSWORD_GUID = "00299570-246d-11d0-a768-00aa006e0529"
DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
FULL_CONTROL = 0x000F01FF

UAC_NORMAL = "512"
UAC_DISABLED = "514"
UAC_DONT_EXPIRE_PASSWD = "66048"  # 512 | 0x10000
UAC_DONT_REQ_PREAUTH = "4194816"  # 512 | 0x400000
UAC_COMPUTER_TRUSTED_FOR_DELEGATION = "528384"  # WORKSTATION_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
UAC_COMPUTER_NORMAL = "4096"  # WORKSTATION_TRUST_ACCOUNT
UAC_DC = "532480"  # SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION (DC reel)
UAC_COMPUTER_PROTO_TRANSITION = (
    "16781312"  # WORKSTATION_TRUST_ACCOUNT | TRUSTED_TO_AUTH_FOR_DELEGATION
)
UAC_KERBEROASTABLE = "512"
UAC_DES_ONLY = "2097664"  # 512 | USE_DES_KEY_ONLY (0x200000)
SID_APPSRV01 = "S-1-5-21-1111-2222-3333-2101"
SID_WEBSRV01 = "S-1-5-21-1111-2222-3333-2102"
SID_DC01 = "S-1-5-21-1111-2222-3333-1000"


def build_mock_connection(
    target: str, credential: Credential, port: int, use_ssl: bool
) -> Connection:
    """Fabrique de connexion compatible `ConnectionFactory`, ignorant les
    parametres reseau (target/port/use_ssl/credential) pour retourner une
    connexion mock pre-peuplee avec le domaine `corp.example`."""
    server = Server("mock-corp-example", get_info=OFFLINE_AD_2012_R2)
    server.info.other["defaultNamingContext"] = [NAMING_CONTEXT]
    server.info.other["dnsHostName"] = [DC_HOSTNAME]
    server.info.other["forestFunctionality"] = ["7"]
    server.info.other["domainFunctionality"] = ["7"]
    server.info.naming_contexts = [NAMING_CONTEXT]

    if credential.principal and credential.secret:
        # Bind authentifie : le mock exige une entree annuaire avec userPassword.
        conn = Connection(
            server,
            user=credential.principal,
            password=credential.secret,
            authentication=SIMPLE,
            client_strategy=MOCK_SYNC,
        )
        _populate(conn)
        conn.strategy.add_entry(
            credential.principal,
            {
                "objectClass": ["user", "person", "organizationalPerson", "top"],
                "userPassword": credential.secret,
                "sAMAccountName": "audit",
            },
        )
    else:
        conn = Connection(server, client_strategy=MOCK_SYNC)
        _populate(conn)
    conn.bind()
    return conn


def _sd(owner: str, *aces: FakeAce) -> bytes:
    return build_security_descriptor(owner, list(aces))


def _populate(conn: Connection) -> None:
    add = conn.strategy.add_entry
    ctx = NAMING_CONTEXT

    add(
        ctx,
        {
            "objectClass": ["domain", "top"],
            "gPLink": f"[LDAP://cn={{11111111-1111-1111-1111-111111111111}},cn=policies,cn=system,{ctx};0]",
            "nTSecurityDescriptor": _sd(
                SID_DOMAIN_ADMINS,
                FakeAce(SID_DOMAIN_ADMINS, FULL_CONTROL),  # legitime
                FakeAce(
                    SID_BOB, RIGHT_DS_CONTROL_ACCESS, object_type_guid=DS_REPL_GET_CHANGES
                ),  # AD-ACL-005 (avec la ligne suivante)
                FakeAce(SID_BOB, RIGHT_DS_CONTROL_ACCESS, object_type_guid=DS_REPL_GET_CHANGES_ALL),
            ),
        },
    )
    add(f"CN=System,{ctx}", {"objectClass": ["container", "top"]})
    add(f"OU=Users,{ctx}", {"objectClass": ["organizationalUnit", "top"], "ou": "Users"})
    add(
        f"OU=Servers,{ctx}",
        {
            "objectClass": ["organizationalUnit", "top"],
            "ou": "Servers",
            "gPLink": f"[LDAP://cn={{22222222-2222-2222-2222-222222222222}},cn=policies,cn=system,{ctx};0]",
        },
    )

    # -- GPO -------------------------------------------------------------
    add(
        f"CN=Policies,CN=System,{ctx}",
        {"objectClass": ["container", "top"]},
    )
    add(
        f"CN={{11111111-1111-1111-1111-111111111111}},CN=Policies,CN=System,{ctx}",
        {
            "objectClass": ["groupPolicyContainer", "top"],
            "displayName": "Default Domain Policy",
            "gPCFileSysPath": "\\\\corp.example\\SYSVOL\\corp.example\\Policies\\{11111111-1111-1111-1111-111111111111}",
            "versionNumber": "3",
            "flags": "0",
            "nTSecurityDescriptor": _sd(
                SID_DOMAIN_ADMINS,
                FakeAce(
                    SID_BOB, RIGHT_GENERIC_WRITE
                ),  # AD-GPO-001, portee critique (racine domaine)
            ),
        },
    )
    add(
        f"CN={{22222222-2222-2222-2222-222222222222}},CN=Policies,CN=System,{ctx}",
        {
            "objectClass": ["groupPolicyContainer", "top"],
            "displayName": "Servers Hardening",
            "gPCFileSysPath": "\\\\corp.example\\SYSVOL\\corp.example\\Policies\\{22222222-2222-2222-2222-222222222222}",
            "versionNumber": "1",
            "flags": "0",
        },
    )
    add(
        f"CN={{33333333-3333-3333-3333-333333333333}},CN=Policies,CN=System,{ctx}",
        {
            "objectClass": ["groupPolicyContainer", "top"],
            "displayName": "Orphaned Legacy Policy",
            "versionNumber": "0",
            "flags": "0",
        },
    )

    # -- Trusts -------------------------------------------------------------
    add(
        f"CN=partner.example,CN=System,{ctx}",
        {
            "objectClass": ["trustedDomain", "top"],
            "trustPartner": "partner.example",
            "trustDirection": "3",
            "trustType": "2",
            "trustAttributes": "0",
        },
    )
    add(
        f"CN=forest.example,CN=System,{ctx}",
        {
            "objectClass": ["trustedDomain", "top"],
            "trustPartner": "forest.example",
            "trustDirection": "3",
            "trustType": "2",
            "trustAttributes": "8",
        },
    )

    # -- Utilisateurs (avec SID et ACL) ------------------------------------------
    user_class = ["user", "person", "organizationalPerson", "top"]
    add(
        f"CN=Alice Admin,OU=Users,{ctx}",
        {
            "objectClass": user_class,
            "objectCategory": "person",
            "sAMAccountName": "alice.admin",
            "objectSid": encode_sid(SID_ALICE),
            "userPrincipalName": "alice.admin@corp.example",
            "userAccountControl": UAC_NORMAL,
            "adminCount": "1",
            "nTSecurityDescriptor": _sd(
                SID_DOMAIN_ADMINS,
                FakeAce(SID_DOMAIN_ADMINS, FULL_CONTROL),  # legitime : ne doit pas etre signale
                FakeAce(SID_SYSTEM, FULL_CONTROL),  # legitime
                FakeAce(SID_HELPDESK, RIGHT_GENERIC_ALL),  # AD-ACL-001
                FakeAce(
                    SID_SVC_SQL,
                    RIGHT_DS_CONTROL_ACCESS,
                    object_type_guid=FORCE_CHANGE_PASSWORD_GUID,
                ),  # AD-ACL-003
            ),
        },
    )
    add(
        f"CN=Bob User,OU=Users,{ctx}",
        {
            "objectClass": user_class,
            "objectCategory": "person",
            "sAMAccountName": "bob.user",
            "objectSid": encode_sid(SID_BOB),
            "userPrincipalName": "bob.user@corp.example",
            "userAccountControl": UAC_NORMAL,
            # Objet non sensible : un GenericAll ici ne doit PAS etre signale.
            "nTSecurityDescriptor": _sd(
                SID_DOMAIN_ADMINS, FakeAce(SID_HELPDESK, RIGHT_GENERIC_ALL)
            ),
        },
    )
    add(
        f"CN=Svc Sql,OU=Users,{ctx}",
        {
            "objectClass": user_class,
            "objectCategory": "person",
            "sAMAccountName": "svc-sql",
            "objectSid": encode_sid(SID_SVC_SQL),
            "userAccountControl": UAC_DONT_EXPIRE_PASSWD,
            "servicePrincipalName": ["MSSQLSvc/sqlsrv01.corp.example:1433"],
            "msDS-SupportedEncryptionTypes": "0",
        },
    )
    add(
        f"CN=Svc Backup,OU=Users,{ctx}",
        {
            "objectClass": user_class,
            "objectCategory": "person",
            "sAMAccountName": "svc-backup",
            "userAccountControl": UAC_DES_ONLY,
            "servicePrincipalName": ["backupagent/backup01.corp.example"],
        },
    )
    add(
        f"CN=Legacy Svc,OU=Users,{ctx}",
        {
            "objectClass": user_class,
            "objectCategory": "person",
            "sAMAccountName": "legacy-svc",
            "userAccountControl": UAC_DONT_REQ_PREAUTH,
        },
    )
    add(
        f"CN=Disabled User,OU=Users,{ctx}",
        {
            "objectClass": user_class,
            "objectCategory": "person",
            "sAMAccountName": "old.employee",
            "userAccountControl": UAC_DISABLED,
        },
    )

    # -- Ordinateurs -----------------------------------------------------------
    computer_class = ["computer", "user", "organizationalPerson", "person", "top"]
    add(
        f"CN=DC01,OU=Servers,{ctx}",
        {
            "objectClass": computer_class,
            "objectCategory": "computer",
            "sAMAccountName": "DC01$",
            "objectSid": encode_sid(SID_DC01),
            "dNSHostName": DC_HOSTNAME,
            "operatingSystem": "Windows Server 2022",
            "userAccountControl": UAC_DC,
        },
    )
    add(
        f"CN=WebSrv01,OU=Servers,{ctx}",
        {
            "objectClass": computer_class,
            "objectCategory": "computer",
            "sAMAccountName": "WEBSRV01$",
            "objectSid": encode_sid(SID_WEBSRV01),
            "dNSHostName": "websrv01.corp.example",
            "operatingSystem": "Windows Server 2022",
            "userAccountControl": UAC_COMPUTER_PROTO_TRANSITION,
            "msDS-AllowedToDelegateTo": [
                f"cifs/{DC_HOSTNAME}",
                "http/appsrv01.corp.example",
            ],
        },
    )
    add(
        f"CN=FileSrv01,OU=Servers,{ctx}",
        {
            "objectClass": computer_class,
            "objectCategory": "computer",
            "sAMAccountName": "FILESRV01$",
            "objectSid": encode_sid(f"{DOMAIN_SID}-2103"),
            "dNSHostName": "filesrv01.corp.example",
            "operatingSystem": "Windows Server 2019",
            "userAccountControl": UAC_COMPUTER_NORMAL,
            "msDS-AllowedToActOnBehalfOfOtherIdentity": _sd(
                SID_DOMAIN_ADMINS, FakeAce(SID_WEBSRV01, FULL_CONTROL)
            ),
        },
    )
    add(
        f"CN=Legacy App Srv,OU=Servers,{ctx}",
        {
            "objectClass": computer_class,
            "objectCategory": "computer",
            "sAMAccountName": "APPSRV01$",
            "dNSHostName": "appsrv01.corp.example",
            "operatingSystem": "Windows Server 2012 R2",
            "userAccountControl": UAC_COMPUTER_TRUSTED_FOR_DELEGATION,
            "msDS-SupportedEncryptionTypes": "0",
            "nTSecurityDescriptor": _sd(
                SID_DOMAIN_ADMINS,
                FakeAce(SID_AUTH_USERS, RIGHT_GENERIC_WRITE),  # AD-ACL-004 (CRITICAL)
            ),
        },
    )

    # -- Groupes (avec imbrication) -----------------------------------------------
    add(
        f"CN=Domain Admins,CN=Users,{ctx}",
        {
            "objectClass": ["group", "top"],
            "sAMAccountName": "Domain Admins",
            "objectSid": encode_sid(SID_DOMAIN_ADMINS),
            "member": [
                f"CN=Alice Admin,OU=Users,{ctx}",
                f"CN=Helpdesk Tier2,CN=Users,{ctx}",
            ],
            "nTSecurityDescriptor": _sd(
                SID_DOMAIN_ADMINS,
                FakeAce(SID_BOB, RIGHT_WRITE_OWNER),  # AD-ACL-002
            ),
        },
    )
    add(
        f"CN=Helpdesk Tier2,CN=Users,{ctx}",
        {
            "objectClass": ["group", "top"],
            "sAMAccountName": "Helpdesk Tier2",
            "objectSid": encode_sid(SID_HELPDESK),
            "member": [f"CN=Bob User,OU=Users,{ctx}"],
        },
    )
