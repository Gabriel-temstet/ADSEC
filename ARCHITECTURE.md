# Architecture

## Vue d'ensemble

```
CLI (typer)
  -> CliContext (config + DB)
       -> Repositories (clients, engagements, scopes, scan_jobs)
       -> ScopeManager (controle central avant toute I/O reseau)
       -> Scheduler (worker pool, rate limiting, circuit breaker, retries)
       -> PluginManager (decouverte + filtrage des CheckPlugin)
```

## Modules (perimetre Phase 2)

### `core/models/`
Modeles pydantic partages : `Client`, `Engagement`, `Scope`, `ScopeEntry`,
`ScanJob`, `ScanEvent`, `CredentialsMetadata`, et les enums associes
(`AccessLevel`, `ScanProfile`, `Severity`, `Confidence`, ...).

### `core/scope/`
`ScopeManager` : evalue si une cible (host, FQDN, IP) est autorisee.
Regle de priorite : une exclusion explicite l'emporte toujours sur une
inclusion. `assert_in_scope()` est le point de controle obligatoire avant
toute operation reseau (a appeler par tout futur collector).

### `core/scheduler/`
- `TokenBucketRateLimiter` : limite le debit de requetes/seconde.
- `CircuitBreaker` : ecarte temporairement une cible (ex: un DC) apres trop
  d'echecs consecutifs.
- `Scheduler` : orchestre des `Task` avec priorites, concurrence globale et
  par cle, timeout, retry (backoff exponentiel + jitter), kill switch
  (`request_stop()`), et arret automatique si le taux d'erreur ou la duree
  maximale configures sont depasses.

### `core/events/`
- `EventBus` : pub/sub interne pour la progression (decouple le moteur de
  la CLI/du logging).
- `AuditLog` : journal JSONL append-only, masquage systematique des motifs
  ressemblant a des secrets.

### `database/`
- `schema/NNNN_*.sql` : migrations versionnees, appliquees automatiquement
  et de maniere idempotente par `apply_migrations()`.
- `repositories/` : un repository par entite (`ClientRepository`,
  `EngagementRepository`, `ScopeRepository`, `ScanJobRepository`). Toutes
  les tables metier portent `engagement_id` pour garantir l'isolation.

### `config/`
- `settings.py` : `AppSettings` (pydantic-settings, prefixe `ADSEC_`).
- `defaults/profiles.yaml` : definition des profils `passive/safe/standard/deep`.
- `defaults/safety.yaml` : parametres de securite operationnelle par defaut
  du scheduler et etat par defaut des actions intrusives (`false`).

### `rules/` (plugin system)
- `base.py` : `CheckPlugin` (classe abstraite, verifie a la definition de
  la sous-classe que toutes les metadonnees obligatoires sont presentes),
  `Finding` (format standardise avec `fingerprint()` de deduplication),
  `NormalizedData` / `ScanContext` (contrat de donnees pour Phase 3+).
- `registry.py` : `PluginManager`, decouverte automatique (package interne
  + entry points `adsec.plugins`), filtrage par niveau d'acces/profil, et
  **exclusion par defaut des plugins `intrusive=True`**.
- `security/ad_sec_000_safe_posture.py` : premier plugin reel, valide que
  `intrusive_actions_enabled` n'est pas active sans decision explicite.

### `cli/`
Typer. Chaque sous-commande (`client`, `engagement`, `scope`, `doctor`)
utilise `CliContext` (config + connexion DB avec migrations deja
appliquees) pour rester independante de la couche de presentation.

## Phase 3 : LDAP discovery

- `collectors/base.py` : contrat `Collector` (`discover` / `collect`),
  `DiscoveryResult`, `CollectionResult` (lignes dict par type d'objet).
- `collectors/ldap/` : `LdapCollector` (verifie le scope avant toute
  connexion, root DSE via `server.info`, recherches users/groups/
  computers/OUs, aucune ecriture), `attributes.py` (SID, userAccountControl,
  FILETIME, DN), `normalizer.py` (dicts bruts -> modeles pydantic valides,
  appartenances aux groupes avec type resolu).
- `credentials/` : `CredentialProvider` (anonyme, environnement, statique).
- `core/engine/pipeline.py` : `ScanPipeline` (ScanJob tracable, discovery
  puis collection via le `Scheduler`, persistance en upsert, execution des
  plugins compatibles, audit log de chaque operation).
- Migration `0002_ad_objects.sql` : forests, domains, sites,
  domain_controllers, ous, users, groups, group_memberships, computers.
- Tests : fixture `tests/fixtures/corp_example.py` (AD fictif via ldap3
  `MOCK_SYNC`, sans AD reel).

Limites connues : les findings produits par les plugins sont retournes
dans le resume du scan mais pas encore persistes (table `findings` a
venir) ; l'imbrication de groupes n'est pas encore aplatie (Phase 5).

## Phase 4, lot 1 : ACL, trusts, findings

- `collectors/ldap/sddl.py` : parseur binaire du security descriptor
  (owner + DACL, ACE standard et OBJECT). Un descripteur malforme retourne
  `None` sans jamais interrompre la collecte des autres objets.
- `collectors/ldap/rights.py` : decodage du masque d'acces, equivalences
  (Full Control = 0x000F01FF, GenericWrite), GUID d'extended rights connus.
- Collecte `nTSecurityDescriptor` avec le controle LDAP SD flags (requis
  sur un AD reel), repli sans controle si le serveur ne le supporte pas.
- Collecte des trusts (`CN=System`, objets `trustedDomain`).
- Plugins : `AD-ACL-001` GenericAll, `AD-ACL-002` WriteDACL/WriteOwner,
  `AD-ACL-003` ForceChangePassword, `AD-ACL-004` GenericWrite,
  `AD-TRUST-001` trust externe sans filtrage SID.
  Ils ne signalent que les droits detenus par un principal NON integre sur
  un objet SENSIBLE (adminCount=1, groupe privilegie, delegation non
  contrainte). Severite HIGH, CRITICAL si le principal est tres large
  (Everyone, Authenticated Users, Domain Users).
- Aucun mapping MITRE ATT&CK n'est renseigne pour ces regles : aucune
  technique ne correspond de facon fiable (regle du produit : ne jamais
  fabriquer de mapping).
- `findings` + `evidence` (migration 0004) : deduplication par
  fingerprint, `first_seen` et statut choisi par le pentester preserves
  lors des re-scans, hash SHA-256 de chaque preuve.
- Un scan qui n'a pas le niveau d'acces requis signale les controles
  ignores dans ses limitations au lieu de les omettre silencieusement.

Limites connues du lot 1 : l'heritage n'est pas recalcule (une ACE heritee
est signalee comme telle, sans remonter a l'OU source) ; les ACL ne sont
collectees que pour users/groups/computers/OUs (pas la racine du domaine
ni les GPO) ; les regles ne remontent pas encore les chemins multi-sauts
(Phase 5).

## Phase 4, lot 2 : Kerberos, GPO, DCSync

- `collectors/ldap/attributes.py` : constantes UAC additionnelles
  (SERVER_TRUST_ACCOUNT, NOT_DELEGATED, USE_DES_KEY_ONLY,
  TRUSTED_TO_AUTH_FOR_DELEGATION), parseur `gPLink` et extraction du GUID
  d'un DN de GPO.
- Le collector LDAP recupere desormais `msDS-AllowedToDelegateTo`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity` (decode en trustees via le
  parseur de security descriptor) et `msDS-SupportedEncryptionTypes` pour
  users/computers, ainsi que les GPO (`CN=Policies,CN=System`) et l'ACL de
  la racine du domaine (`_search_domain_root`).
- Modele `GroupPolicy`/`GpoLink` (migration 0005) ; les liens sont calcules
  en normalisation a partir des `gPLink` des OUs et de la racine du domaine.
- `rules/kerberos/checks.py` (6 controles) : `AD-KRB-001` AS-REP roasting,
  `AD-KRB-002` Kerberoasting, `AD-KRB-003` delegation non contrainte (hors
  DC, identifies via SERVER_TRUST_ACCOUNT), `AD-KRB-004` delegation
  contrainte avec transition de protocole (severite HIGH si une cible est
  un DC), `AD-KRB-005` RBCD configuree, `AD-KRB-006` chiffrement faible
  (DES/pas d'AES).
- `rules/acl/ad_acl_005_replication_rights.py` : droits DCSync
  (DS-Replication-Get-Changes + -All) sur la racine du domaine, hors
  principaux integres.
- `rules/gpo/checks.py` : `AD-GPO-001` GPO modifiable par un principal non
  integre (CRITICAL si liee a la racine du domaine ou a Domain
  Controllers), `AD-GPO-002` GPO non liee.
- `rules/factory.py` : construction homogene des findings (pourquoi
  detecte / pourquoi risque / faux positif possible), reutilisee par tous
  les nouveaux controles.
- Aucun cassage de ticket, aucune demande TGS/AS, aucune usurpation S4U :
  ces controles lisent uniquement les attributs LDAP deja collectes.

Limites connues du lot 2 : le contenu des GPO (GptTmpl.inf, scripts,
taches planifiees dans SYSVOL) necessite un acces SMB, pas encore
implemente ; les liens de GPO au niveau des sites AD ne sont pas
collectes (seulement domaine + OUs).

## Phase 4, lot 3 : SMB, DNS (Phase 4 complete)

- `collectors/smb/session.py` : `SmbSession` (contrat), `ImpacketSmbSession`
  (implementation reelle sur `impacket.smbconnection.SMBConnection`).
  Operations en lecture seule : negociation (dialecte, signing), liste des
  partages, `connectTree` pour verifier l'accessibilite (pas de lecture de
  fichier). Une fabrique de session est injectable pour les tests
  (`SessionFactory`), comme `ConnectionFactory` pour LDAP.
- `collectors/smb/collector.py` : `SmbCollector` (discover = negociation,
  collect = partages + test d'acces anonyme par partage, IPC$/ADMIN$
  exclus du test).
- `collectors/dns/probe.py` : `DnsProbe` (contrat), `DnspythonProbe`
  (implementation reelle sur `dnspython`) : accessibilite (requete
  CHAOS TXT version.bind), transfert de zone (AXFR), recursion (requete
  standard vers un domaine externe). Aucune mise a jour dynamique
  (nsupdate) n'est tentee : ce serait une operation d'ecriture, exclue du
  perimetre SAFE par defaut.
- `collectors/dns/collector.py` : `DnsCollector`.
- Migration 0006 : `smb_hosts`, `smb_shares`, `dns_zone_checks`.
- Plugins : `AD-SMB-001` SMBv1 actif, `AD-SMB-002` signature non exigee
  (HIGH si la cible est un DC), `AD-SMB-003` session anonyme/invite
  acceptee, `AD-SMB-004` partage lisible anonymement (partages caches
  exclus) ; `AD-DNS-001` transfert de zone autorise, `AD-DNS-002`
  recursion ouverte.
- `ScanPipeline` execute SMB et DNS sur la meme cible que LDAP (le DC),
  uniquement si le profil actif autorise les categories `smb`/`dns`
  (`safe` les exclut, `standard`/`deep` les incluent). Ils fonctionnent
  independamment du niveau d'acces LDAP obtenu (protocoles distincts,
  testables meme sans identifiants).

Limites connues du lot 3 (et donc de la Phase 4 dans son ensemble) :
aucun test de mise a jour DNS dynamique (necessiterait une ecriture) ;
pas d'enumeration NTFS/ACL de partage au-dela de l'accessibilite binaire ;
testable uniquement via des doubles de test dans ce depot (aucun serveur
SMB/DNS reel disponible pour la validation) - un passage sur un
environnement de lab est recommande avant mission.

## Phase 5, lot 1 : moteur de graphe et chemins d'attaque

- `graph/models.py` : `GraphNode`, `GraphEdge` (avec `RelationConfidence`
  reutilise du reste du produit), `AttackPath`.
- `graph/builder.py` : construit le graphe UNIQUEMENT a partir des donnees
  deja collectees (users/groups/computers/memberships/acls/gpos) - aucune
  requete reseau supplementaire. Aretes produites : `MEMBER_OF`
  (appartenances), `CAN_CONTROL` (GenericAll/WriteDACL), `OWNS`
  (WriteOwner), `CAN_WRITE` (GenericWrite), `CAN_RESET_PASSWORD`
  (ForceChangePassword), `CAN_DCSYNC` (droits de replication sur la racine
  du domaine, CONFIRMED si Get-Changes + Get-Changes-All, POTENTIAL
  sinon), `APPLIES_TO` (lien de GPO vers son perimetre). Les trustees bien
  connus (SYSTEM, Domain Admins sur lui-meme...) ne produisent pas d'arete
  (`rules/acl/well_known_sids.py`, deja utilise par les plugins ACL).
- `graph/path_finder.py` : Dijkstra sur le graphe *inverse* depuis chaque
  actif critique, ce qui donne en un seul parcours les chemins depuis
  TOUS les noeuds vers cette cible. Cout d'une arete = fonction de sa
  confiance (CONFIRMED < POTENTIAL < INFERRED), pour preferer les chemins
  les plus fiables a longueur egale. Plafond de 8 sauts et de 200 chemins
  par cible pour rester exploitable.
- Actifs critiques (`critical_targets`) : groupes integres a privileges
  (Domain Admins, Enterprise Admins, Administrators...), ordinateurs
  identifies comme controleurs de domaine (flag SERVER_TRUST_ACCOUNT), et
  le domaine lui-meme (portee d'un DCSync reussi).
- Migration 0007 (`attack_paths`) : un re-scan en profil `deep` **remplace**
  l'ensemble des chemins (ils sont deterministes a partir des donnees
  courantes, contrairement aux findings qui preservent un statut).
- `ScanPipeline` calcule et persiste les chemins uniquement si le profil
  actif autorise la categorie `attackpaths` (seul `deep` le fait).
- CLI : `adsec graph targets <engagement>`, `adsec graph show <engagement>
  <target_dn> [--limit]`.
- Valeur demontree au-dela des findings ACL seuls : le graphe relie des
  ACE sur des objets NON sensibles (ex: un groupe de support avec
  GenericAll sur un compte de service ordinaire) a un chemin complet vers
  un actif critique si ce compte detient par ailleurs un droit dangereux
  (ex: DCSync) - une chaine a 2+ sauts qu'aucun controle individuel ne
  peut voir isolement.

Limites connues du lot 1 : pas d'edges `HAS_SESSION`/`ADMIN_OF` (necessite
une collecte de sessions/groupes locaux, hors perimetre actuel) ; la
delegation Kerberos (non contrainte, contrainte+transition, RBCD) n'est pas
encore traduite en aretes de graphe (uniquement en findings) ; les liens de
GPO ne sont pas developpes jusqu'aux ordinateurs membres de l'OU ciblee.

## Phase 5, lots 2-3 : correlation, modele de risque, export BloodHound

- `graph/correlation.py` : relie un finding a un chemin d'attaque quand ce
  chemin DEMARRE exactement par la relation que le finding decrit (meme
  principal, meme relation, meme objet cible en premier saut). Le cas
  `AD-ACL-005` (DCSync) est traite a part : sa cible est toujours le
  domaine, independamment du DN exact stocke dans `affected_assets`
  (naming context) vs l'identifiant de noeud du graphe (fqdn). Un bug reel
  a ete corrige pendant le developpement : sans verification du premier
  saut, un finding pouvait se retrouver correle a un chemin emprunte par
  un AUTRE objet partageant le meme type de droit depuis le meme
  principal.
- `rules/risk.py` : `RiskAssessment` separe toujours Severity, Confidence,
  Impact, Exploitability, Exposure. `RISK_PROFILES` est une table statique
  (impact/exploitabilite de base par `rule_id`), jamais une formule
  calculee. Si le finding est correle a au moins un chemin d'attaque reel,
  l'impact est releve vers `domain_wide` et la raison exacte est tracee
  dans `explanation`. `adsec findings show` affiche les 5 dimensions
  separement, jamais fusionnees en un score unique.
- `export/bloodhound/` : couche d'adaptation entre le graphe interne et un
  format compatible avec les outils publics utilises par BloodHound (6
  fichiers JSON : users/groups/computers/domains/gpos/relationships).
  Sous-ensemble raisonnable (ObjectIdentifier, Properties de base,
  relations), pas une fidelite complete au schema BloodHound (pas d'Aces
  imbriquees par objet, pas de sessions). `adsec export bloodhound`.

## Phase 6-7 : exports, rapports, baseline/diff, sanitization

- `export/json_export.py`, `export/csv_export.py` : export brut des
  findings (et leurs preuves pour le JSON).
- `reporting/data.py` : `ReportData`, structure commune aux deux types de
  rapport, construite une seule fois puis rendue dans differents formats.
- `reporting/markdown.py`, `reporting/html.py` : rendu autonome (aucune
  dependance de templating externe ajoutee), avec echappement HTML
  systematique (`html.escape`) pour eviter toute injection dans un rapport
  genere a partir de donnees AD (un attaquant pourrait nommer un objet AD
  `<script>...`).
- `reporting/sanitizer.py` : masque IP/emails/secrets dans les rapports
  narratifs uniquement (`--sanitize`), jamais dans les exports JSON/CSV
  (usage interne).
- `reporting/limitations.py` : les limitations affichees dans un rapport
  sont derivees de ce qui a ete collecte (tables vides = limitation
  signalee), faute de persistance individuelle des limitations de chaque
  scan a ce jour (limitation connue, documentee dans `REPORTING.md`).
- Migration 0009 (`baselines`) : `adsec baseline create/list`, `adsec
  diff`. Le diff compare l'etat courant a un **instantane** (baseline),
  pas deux scans historiques arbitraires : les findings sont mis a jour
  en place a chaque scan (pas d'historique multi-scans interrogeable
  aujourd'hui).
- CLI : `adsec report generate`, `adsec baseline create/list`, `adsec
  diff`, `adsec export bloodhound`.

## Phase 8 : packaging, Docker, documentation

- `pyproject.toml` : `[tool.setuptools.package-data]` inclut les YAML de
  configuration et les migrations SQL dans le paquet installe - un bug
  reel a ete trouve et corrige ici : sans cette declaration, `pip install`
  produisait un paquet fonctionnellement casse (profils de scan et schema
  de base introuvables a l'execution). Verifie par une installation dans
  un environnement virtuel propre (`adsec doctor run` apres installation
  du wheel).
- `Dockerfile` : image multi-stage (build du wheel puis installation),
  utilisateur non-root, donnees dans un volume (`/data`). **Non teste par
  une construction reelle** : aucun demon Docker n'etait disponible dans
  l'environnement de developpement. A valider avant un usage en
  production.
- `.github/workflows/ci.yml` : lint (ruff), format, types (mypy --strict),
  securite (bandit, pip-audit), tests (pytest), build (wheel+sdist),
  dependance systeme `libkrb5-dev` pour impacket.

## Limites connues, produit dans son ensemble

- **Jamais valide contre un Active Directory reel.** Tous les collectors
  (LDAP, SMB, DNS) sont developpes et testes contre des doubles de test
  (mock ldap3, sessions/sondes factices) — necessaire dans cet
  environnement de developpement sans acces reseau a un AD. Un passage
  sur un lab AD reel est fortement recommande avant toute mission.
- Pas d'edges de graphe pour la delegation Kerberos (seulement des
  findings separes) ni pour les sessions/administrateurs locaux (non
  collectes).
- Le contenu des GPO (SYSVOL) n'est pas analyse, seulement les metadonnees
  et permissions LDAP.
- Le diff ne compare qu'a une baseline (instantane), pas deux scans
  historiques arbitraires.
- L'export BloodHound est un sous-ensemble raisonnable, pas une fidelite
  complete au schema (voir plus haut).
