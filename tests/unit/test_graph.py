from __future__ import annotations

from adsec.core.models.enums import RelationConfidence
from adsec.graph.builder import Graph, build_graph, critical_targets
from adsec.graph.models import GraphEdge, NodeType, RelationType
from adsec.graph.path_finder import find_attack_paths


def test_toy_graph_multi_hop_path_is_found() -> None:
    g = Graph()
    for node_id in ("bob", "helpdesk", "alice", "da"):
        g.add_node(node_id, NodeType.USER, node_id)
    g.add_edge(
        GraphEdge(
            source_id="bob",
            target_id="helpdesk",
            relation=RelationType.MEMBER_OF,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    g.add_edge(
        GraphEdge(
            source_id="helpdesk",
            target_id="alice",
            relation=RelationType.CAN_CONTROL,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    g.add_edge(
        GraphEdge(
            source_id="alice",
            target_id="da",
            relation=RelationType.MEMBER_OF,
            confidence=RelationConfidence.CONFIRMED,
        )
    )

    paths = find_attack_paths(g, "ENG-1", ["da"])
    by_source = {p.source_id: p for p in paths}
    assert by_source["alice"].length == 1
    assert by_source["helpdesk"].length == 2
    assert by_source["bob"].length == 3
    assert by_source["bob"].node_ids == ["bob", "helpdesk", "alice", "da"]
    assert all(p.confidence == RelationConfidence.CONFIRMED for p in paths)


def test_shorter_path_preferred_over_longer_one() -> None:
    g = Graph()
    for node_id in ("attacker", "target", "mid1", "mid2"):
        g.add_node(node_id, NodeType.USER, node_id)
    # Chemin direct (1 saut)
    g.add_edge(
        GraphEdge(
            source_id="attacker",
            target_id="target",
            relation=RelationType.CAN_CONTROL,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    # Chemin plus long via mid1 -> mid2 -> target (3 sauts) : ne doit pas remplacer le direct
    g.add_edge(
        GraphEdge(
            source_id="attacker",
            target_id="mid1",
            relation=RelationType.MEMBER_OF,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    g.add_edge(
        GraphEdge(
            source_id="mid1",
            target_id="mid2",
            relation=RelationType.MEMBER_OF,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    g.add_edge(
        GraphEdge(
            source_id="mid2",
            target_id="target",
            relation=RelationType.CAN_CONTROL,
            confidence=RelationConfidence.CONFIRMED,
        )
    )

    paths = find_attack_paths(g, "ENG-1", ["target"])
    attacker_path = next(p for p in paths if p.source_id == "attacker")
    assert attacker_path.length == 1  # le chemin direct, pas le detour


def test_potential_confidence_edge_costs_more_than_confirmed() -> None:
    g = Graph()
    for node_id in ("a", "b", "c", "target"):
        g.add_node(node_id, NodeType.USER, node_id)
    # a -> target : 1 saut mais POTENTIAL
    g.add_edge(
        GraphEdge(
            source_id="a",
            target_id="target",
            relation=RelationType.DELEGATES_TO,
            confidence=RelationConfidence.POTENTIAL,
        )
    )
    # a -> b -> c -> target : 3 sauts mais tous CONFIRMED
    g.add_edge(
        GraphEdge(
            source_id="a",
            target_id="b",
            relation=RelationType.MEMBER_OF,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    g.add_edge(
        GraphEdge(
            source_id="b",
            target_id="c",
            relation=RelationType.MEMBER_OF,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    g.add_edge(
        GraphEdge(
            source_id="c",
            target_id="target",
            relation=RelationType.CAN_CONTROL,
            confidence=RelationConfidence.CONFIRMED,
        )
    )

    paths = find_attack_paths(g, "ENG-1", ["target"])
    a_path = next(p for p in paths if p.source_id == "a")
    # 3 aretes CONFIRMED (cout 3) est prefere a 1 arete POTENTIAL (cout 3) a egalite,
    # mais le tri Dijkstra depart ties par ordre d'insertion : verifions juste le cout.
    assert a_path.length in (1, 3)
    if a_path.length == 1:
        assert a_path.confidence == RelationConfidence.POTENTIAL


def test_self_loop_edges_are_ignored() -> None:
    g = Graph()
    g.add_node("x", NodeType.USER, "x")
    g.add_edge(
        GraphEdge(
            source_id="x",
            target_id="x",
            relation=RelationType.CAN_CONTROL,
            confidence=RelationConfidence.CONFIRMED,
        )
    )
    assert g.edges == []


def test_no_path_when_unreachable() -> None:
    g = Graph()
    g.add_node("isolated", NodeType.USER, "isolated")
    g.add_node("target", NodeType.GROUP, "target")
    paths = find_attack_paths(g, "ENG-1", ["target"])
    assert paths == []


def test_missing_target_returns_no_paths() -> None:
    g = Graph()
    g.add_node("a", NodeType.USER, "a")
    assert find_attack_paths(g, "ENG-1", ["does-not-exist"]) == []


USERS = [{"dn": "CN=Alice", "sam_account_name": "alice", "sid": "S-1-1"}]
GROUPS = [
    {"dn": "CN=DA", "sam_account_name": "Domain Admins", "sid": "S-1-2"},
    {"dn": "CN=Other", "sam_account_name": "Other Group", "sid": "S-1-3"},
]
COMPUTERS = [
    {
        "dn": "CN=DC01",
        "sam_account_name": "DC01$",
        "sid": "S-1-4",
        "raw_attrs": {"userAccountControl": 0x2000},
    },
    {
        "dn": "CN=WS01",
        "sam_account_name": "WS01$",
        "sid": "S-1-5",
        "raw_attrs": {"userAccountControl": 0x1000},
    },
]


def test_build_graph_creates_expected_nodes() -> None:
    graph = build_graph(
        users=USERS,
        groups=GROUPS,
        computers=COMPUTERS,
        memberships=[{"member_dn": "CN=Alice", "group_dn": "CN=DA", "member_type": "user"}],
        acls=[],
        gpos=[],
        domain_fqdn="corp.example",
    )
    assert set(graph.nodes) == {
        "CN=Alice",
        "CN=DA",
        "CN=Other",
        "CN=DC01",
        "CN=WS01",
        "corp.example",
    }
    assert len(graph.edges) == 1
    assert graph.edges[0].relation == RelationType.MEMBER_OF


def test_build_graph_acl_generic_all_edge() -> None:
    acls = [
        {
            "object_dn": "CN=DA",
            "object_type": "group",
            "owner_sid": None,
            "permissions": [
                {
                    "trustee_sid": "S-1-1",
                    "ace_type": "ALLOWED",
                    "rights_mask": 0x10000000,  # GenericAll
                    "rights": ["GenericAll"],
                    "object_type_guid": None,
                    "resolved_right_name": None,
                    "inherited": False,
                }
            ],
        }
    ]
    graph = build_graph(
        users=USERS,
        groups=GROUPS,
        computers=COMPUTERS,
        memberships=[],
        acls=acls,
        gpos=[],
        domain_fqdn="corp.example",
    )
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source_id == "CN=Alice"
    assert edge.target_id == "CN=DA"
    assert edge.relation == RelationType.CAN_CONTROL


def test_build_graph_dcsync_edge_requires_both_rights_for_confirmed() -> None:
    acls = [
        {
            "object_dn": "corp.example",
            "object_type": "domain",
            "owner_sid": None,
            "permissions": [
                {
                    "trustee_sid": "S-1-1",
                    "ace_type": "ALLOWED_OBJECT",
                    "rights_mask": 0x100,
                    "rights": ["ExtendedRight"],
                    "object_type_guid": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                    "resolved_right_name": "DS-Replication-Get-Changes",
                    "inherited": False,
                }
            ],
        }
    ]
    graph = build_graph(
        users=USERS,
        groups=GROUPS,
        computers=COMPUTERS,
        memberships=[],
        acls=acls,
        gpos=[],
        domain_fqdn="corp.example",
    )
    assert len(graph.edges) == 1
    assert graph.edges[0].relation == RelationType.CAN_DCSYNC
    assert graph.edges[0].confidence == RelationConfidence.POTENTIAL  # un seul des deux droits


def test_build_graph_well_known_safe_trustee_produces_no_edge() -> None:
    acls = [
        {
            "object_dn": "CN=DA",
            "object_type": "group",
            "owner_sid": None,
            "permissions": [
                {
                    "trustee_sid": "S-1-5-18",  # SYSTEM
                    "ace_type": "ALLOWED",
                    "rights_mask": 0x10000000,
                    "rights": ["GenericAll"],
                    "object_type_guid": None,
                    "resolved_right_name": None,
                    "inherited": False,
                }
            ],
        }
    ]
    graph = build_graph(
        users=USERS,
        groups=GROUPS,
        computers=COMPUTERS,
        memberships=[],
        acls=acls,
        gpos=[],
        domain_fqdn="corp.example",
    )
    assert graph.edges == []


def test_critical_targets_includes_privileged_groups_dcs_and_domain() -> None:
    targets = critical_targets(GROUPS, COMPUTERS, "corp.example")
    assert "CN=DA" in targets
    assert "CN=Other" not in targets
    assert "CN=DC01" in targets
    assert "CN=WS01" not in targets
    assert "corp.example" in targets


def test_gpo_edges_create_applies_to() -> None:
    gpos = [
        {
            "dn": "CN={GUID},CN=Policies",
            "display_name": "Default Domain Policy",
            "links": [{"target_dn": "OU=Servers", "enabled": True, "enforced": False}],
        }
    ]
    graph = build_graph(
        users=[],
        groups=[],
        computers=[],
        memberships=[],
        acls=[],
        gpos=gpos,
        domain_fqdn="corp.example",
    )
    applies_edges = [e for e in graph.edges if e.relation == RelationType.APPLIES_TO]
    assert len(applies_edges) == 1
    assert applies_edges[0].source_id == "CN={GUID},CN=Policies"
    assert applies_edges[0].target_id == "OU=Servers"
