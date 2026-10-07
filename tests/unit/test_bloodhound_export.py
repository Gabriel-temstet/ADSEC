from __future__ import annotations

from adsec.core.models.ad_objects import ADComputer, ADGroup, ADUser, Domain
from adsec.core.models.gpo import GroupPolicy
from adsec.export.bloodhound.adapter import build_export
from adsec.graph.builder import Graph, build_graph

USER = ADUser(
    engagement_id="E",
    domain_id="D",
    dn="CN=Alice",
    sam_account_name="alice",
    sid="S-1-1",
    admin_count=True,
)
USER_NO_SID = ADUser(
    engagement_id="E",
    domain_id="D",
    dn="CN=Legacy",
    sam_account_name="legacy",
)
GROUP = ADGroup(
    engagement_id="E",
    domain_id="D",
    dn="CN=DA",
    sam_account_name="Domain Admins",
    sid="S-1-2",
    privileged=True,
)
COMPUTER = ADComputer(
    engagement_id="E",
    domain_id="D",
    dn="CN=DC01",
    sam_account_name="DC01$",
    sid="S-1-3",
    dns_hostname="dc01.corp.example",
)
DOMAIN = Domain(engagement_id="E", fqdn="corp.example", naming_context="DC=corp,DC=example")
GPO = GroupPolicy(
    engagement_id="E",
    domain_id="D",
    guid="11111111-1111-1111-1111-111111111111",
    dn="CN={GUID},CN=Policies",
    display_name="Default Domain Policy",
)


def test_build_users_uses_sid_when_available() -> None:
    from adsec.export.bloodhound.adapter import build_users

    result = build_users([USER, USER_NO_SID])
    assert result[0]["ObjectIdentifier"] == "S-1-1"
    assert result[0]["adsec_identifier_is_dn"] is False
    assert result[0]["Properties"]["admincount"] is True
    assert result[1]["ObjectIdentifier"] == "CN=Legacy"
    assert result[1]["adsec_identifier_is_dn"] is True  # repli sur le DN, signale explicitement


def test_build_groups_flags_privileged() -> None:
    from adsec.export.bloodhound.adapter import build_groups

    result = build_groups([GROUP])
    assert result[0]["Properties"]["highvalue"] is True


def test_build_domains_uses_fqdn_as_identifier() -> None:
    from adsec.export.bloodhound.adapter import build_domains

    result = build_domains(DOMAIN)
    assert result[0]["ObjectIdentifier"] == "corp.example"


def test_build_relationships_maps_relation_types_and_skips_unresolved_nodes() -> None:
    graph = build_graph(
        users=[USER.model_dump()],
        groups=[GROUP.model_dump()],
        computers=[COMPUTER.model_dump()],
        memberships=[{"member_dn": "CN=Alice", "group_dn": "CN=DA", "member_type": "user"}],
        acls=[
            {
                "object_dn": "CN=DA",
                "object_type": "group",
                "owner_sid": None,
                "permissions": [
                    {
                        "trustee_sid": "S-1-1",
                        "ace_type": "ALLOWED",
                        "rights_mask": 0x10000000,
                        "rights": ["GenericAll"],
                        "object_type_guid": None,
                        "resolved_right_name": None,
                        "inherited": False,
                    }
                ],
            }
        ],
        gpos=[],
        domain_fqdn="corp.example",
    )
    export = build_export(
        graph=graph, users=[USER], groups=[GROUP], computers=[COMPUTER], domain=DOMAIN, gpos=[GPO]
    )
    rels = {(r["source"], r["relationtype"], r["target"]) for r in export.relationships}
    assert ("CN=Alice", "MemberOf", "CN=DA") in rels
    assert ("CN=Alice", "GenericAll", "CN=DA") in rels
    for r in export.relationships:
        if r["relationtype"] == "GenericAll":
            assert r["isacl"] is True
        if r["relationtype"] == "MemberOf":
            assert r["isacl"] is False


def test_build_export_produces_all_six_collections() -> None:
    graph = Graph()
    export = build_export(
        graph=graph, users=[USER], groups=[GROUP], computers=[COMPUTER], domain=DOMAIN, gpos=[GPO]
    )
    assert len(export.users) == 1
    assert len(export.groups) == 1
    assert len(export.computers) == 1
    assert len(export.domains) == 1
    assert len(export.gpos) == 1
    assert export.relationships == []  # graphe vide


def test_writer_creates_six_json_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json

    from adsec.export.bloodhound.writer import write_bloodhound_export

    graph = Graph()
    export = build_export(
        graph=graph, users=[USER], groups=[GROUP], computers=[COMPUTER], domain=DOMAIN, gpos=[GPO]
    )
    paths = write_bloodhound_export(export, tmp_path / "out")
    assert len(paths) == 6
    assert all(p.exists() for p in paths)
    users_payload = json.loads((tmp_path / "out" / "users.json").read_text())
    assert users_payload["meta"]["type"] == "users"
    assert users_payload["meta"]["count"] == 1
    assert users_payload["data"][0]["ObjectIdentifier"] == "S-1-1"
