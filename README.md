# ADSEC

Plateforme professionnelle d'audit et de pentest Active Directory,
**safe par defaut**, destinee a un cabinet de cybersecurite dans le cadre
de missions autorisees.

> Etat actuel : **les 8 phases du plan de developpement sont completes**
> (voir `docs/ROADMAP.md`). Collecte LDAP complete (users, groups,
> computers, OUs, ACL, trusts, GPO, Kerberos) et collecte SMB/DNS ; 21
> controles avec findings persistes et deduplication ; moteur de graphe et
> chemins d'attaque (profil `deep`) correles aux findings avec un modele
> de risque explicite ; export BloodHound-compatible ; rapports executif
> et technique (Markdown/HTML), export JSON/CSV, sanitization, baseline et
> diff. Reste hors perimetre : validation sur un AD reel (tout a ete
> developpe et teste contre des doubles de test, voir SECURITY.md et
> TROUBLESHOOTING.md), et des ameliorations possibles listees dans
> `docs/ROADMAP.md` et `ARCHITECTURE.md` (limites connues par phase).

## Principes

- **SAFE / NON-DESTRUCTIF par defaut** : aucune commande ne modifie l'AD audite.
- **Scope enforcement central** : toute cible est verifiee par le `ScopeManager`
  avant la moindre operation reseau.
- **Multi-client / multi-engagement** : isolation stricte des donnees par
  `engagement_id`.
- **Intrusif = opt-in explicite**, jamais active par defaut.


![Demo ADSEC](docs/demo.gif)
*Demo hors-ligne sur un domaine fictif (`corp.example`) : aucun AD reel n'est
contacte. Le GIF se regenere avec `demo/make_gif.sh` (voir `demo/README.md`).*

## Installation rapide

```bash
pip install -e ".[dev]"
adsec doctor run
```

Voir `INSTALL.md` et `QUICKSTART.md` pour le detail.

## Documentation

- `INSTALL.md` — installation et prerequis (pip ou Docker)
- `QUICKSTART.md` — premier engagement en 5 minutes
- `ARCHITECTURE.md` — architecture detaillee du produit
- `PLUGIN_DEVELOPMENT.md` — ecrire un nouveau `CheckPlugin`
- `RULE_DEVELOPMENT.md` — conventions des regles de detection (factory,
  correlation, profil de risque)
- `REPORTING.md` — generation de rapports, sanitization, baseline/diff
- `SECURITY.md` — modele de securite et gestion des credentials
- `TROUBLESHOOTING.md` — depannage
- `docs/ROADMAP.md` — phases de developpement
