# Quickstart

Premier engagement en quelques commandes.

```bash
# 1. Verifier l'environnement
adsec doctor run

# 2. Creer un client
adsec client create ACME

# 3. Creer un engagement pour ce client
adsec engagement create ACME ACME-2026-001 \
    --roe "ROE-2026-001" \
    --operator "gab" \
    --profile standard

# 4. Definir le scope de la mission
adsec scope add ACME-2026-001 domain acme.local
adsec scope add ACME-2026-001 host "*.acme.local"
adsec scope add ACME-2026-001 network 10.10.0.0/16
adsec scope add ACME-2026-001 host-exclude production.acme.local

# 5. Verifier le scope
adsec scope show ACME-2026-001
adsec scope test ACME-2026-001 dc01.acme.local
adsec scope test ACME-2026-001 production.acme.local

# 6. Voir le detail de l'engagement
adsec engagement show ACME-2026-001
```

## Lancer un scan LDAP (Phase 3)

```bash
# Authentification optionnelle (bind anonyme si absentes)
export ADSEC_LDAP_BIND_DN="CN=audit,CN=Users,DC=acme,DC=local"
export ADSEC_LDAP_BIND_PASSWORD="..."

adsec scan run ACME-2026-001 dc01.acme.local --profile safe
adsec scan inventory ACME-2026-001
```

La cible doit etre dans le scope (sinon le scan est refuse avant toute
connexion). Un re-scan met a jour les objets existants sans doublons.
Le profil `passive` ne fait que la decouverte (root DSE), sans collecte.

## Consulter les findings

```bash
adsec findings list ACME-2026-001 --severity high
adsec findings show ACME-2026-001 <id>
adsec findings status ACME-2026-001 <id> false_positive
```

Les controles ACL et trusts necessitent un bind authentifie ; sans
identifiants, le scan les liste comme ignores. Les trusts sont analyses
a partir du profil `standard`.

## Chemins d'attaque (profil deep)

```bash
adsec scan run ACME-2026-001 dc01.acme.local --profile deep
adsec graph targets ACME-2026-001
adsec graph show ACME-2026-001 "CN=Domain Admins,CN=Users,DC=acme,DC=local"
```

Le calcul des chemins d'attaque n'est effectue qu'en profil `deep`. Un
re-scan remplace l'ensemble des chemins precedents (ils sont recalcules a
partir des donnees courantes).

## Rapports et export

```bash
# Rapport pour le client (resume, pas de preuves brutes)
adsec report generate ACME-2026-001 --kind executive --format html

# Rapport technique complet, sanitise pour diffusion large
adsec report generate ACME-2026-001 --kind technical --format markdown --sanitize

# Export brut pour une plateforme externe / un tableur
adsec report generate ACME-2026-001 --format json
adsec report generate ACME-2026-001 --format csv

# Export compatible avec les outils publics utilises par BloodHound
adsec export bloodhound ACME-2026-001
```

Voir `REPORTING.md` pour le detail de chaque format et de la sanitisation.

## Suivre un environnement dans le temps

```bash
adsec baseline create ACME-2026-001 --label "Audit initial"
# ... nouveau scan quelques mois plus tard ...
adsec diff ACME-2026-001
```

## Et ensuite ?

Les 8 phases du plan de developpement sont completes — voir
`docs/ROADMAP.md` pour le detail et `ARCHITECTURE.md` pour les limites
connues (notamment : jamais valide contre un AD reel, uniquement contre
des doubles de test).
