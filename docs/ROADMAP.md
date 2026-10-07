# Roadmap

- [x] **Phase 1** — Architecture, modeles, schema SQLite, interfaces,
      strategie de securite et de tests (design uniquement, sans code).
- [x] **Phase 2** — CLI, configuration, engagement, scope, SQLite
      (migrations + repositories), logging structure, plugin manager,
      scheduler.
- [x] **Phase 3** — LDAP discovery : users, groups, computers, domains, OUs
      (collector LDAP, normalisation, pipeline de scan, `adsec scan run/inventory`,
      fixture `corp.example`).
- [x] **Phase 4** — ACL, GPO, Kerberos, SMB, DNS, trusts, decoupee en 3 lots :
  - [x] **Lot 1** : ACL (4 controles), trusts (1 controle), persistance des
        findings + evidence avec deduplication, `adsec findings`.
  - [x] **Lot 2** : Kerberos (AS-REP, Kerberoast, delegations, RBCD, chiffrement faible), droits de replication (DCSync), GPO (metadonnees/liens/ACL).
  - [x] **Lot 3** : SMB (SMBv1, signing, session anonyme, partages) + DNS (transfert de zone, recursion).
- [x] **Phase 5** — Graph engine, attack paths, correlation, risk model (3 lots) :
  - [x] **Lot 1** : moteur de graphe (nodes/edges a partir des donnees deja collectees), recherche de chemins vers Domain Admins/Enterprise Admins/Administrators/DCs/domaine (DCSync), persistance, `adsec graph targets/show`.
  - [x] **Lot 2** : correlation findings <-> chemins d'attaque (`graph/correlation.py`, table `finding_attack_paths`), modele de risque explicite separant Severity/Confidence/Impact/Exploitability/Exposure (`rules/risk.py`), affiche par `adsec findings show`.
  - [x] **Lot 3** : export BloodHound-compatible (`adsec export bloodhound`, 6 fichiers JSON).
- [x] **Phase 6** — Evidence store (deja en place en Phase 4 : table
      `evidence`, hash SHA-256 par preuve), export BloodHound-compatible
      (Phase 5 lot 3), export JSON/CSV des findings (`adsec report
      generate --format json|csv`).
- [x] **Phase 7** — Rapport executif et technique (Markdown + HTML,
      `adsec report generate --kind executive|technical`), baseline et
      diff (`adsec baseline create/list`, `adsec diff`), sanitization
      (`--sanitize`, masque IP/emails/secrets dans les rapports narratifs).
- [x] **Phase 8** — Fixture `corp.example` (deja en place depuis la Phase
      3, enrichie a chaque phase suivante), documentation complete (ce
      fichier plus les 9 fichiers `.md` a la racine), CI GitHub Actions
      (lint/format/types/securite/tests/build), packaging (wheel + sdist
      verifies, donnees de package — YAML/SQL — correctement incluses),
      Dockerfile (image minimale, utilisateur non-root, non teste faute
      de demon Docker dans l'environnement de developpement).

## Contrats deja stabilises (a ne pas casser dans les phases suivantes)

- `ScopeManager` (`assert_in_scope`, `assert_intrusive_allowed`)
- `Scheduler` / `Task` / `TaskResult` (voir `core/scheduler/scheduler.py`)
- `CheckPlugin` / `Finding` / `NormalizedData` / `ScanContext`
- Schema SQLite Phases 2-7 (0001 a 0009) (migrations additives uniquement a partir de la
  Phase 3, jamais de modification retroactive de `0001_initial.sql`)
