# PyHunter

Outil en ligne de commande qui analyse le trafic réseau (PCAP) et les journaux
d'authentification (Linux `auth.log`, Windows Security EVTX) d'une machine
compromise en laboratoire, **sans SIEM**, pour détecter l'attaque, la qualifier
(MITRE ATT&CK, Cyber Kill Chain) et la documenter.

Module CyberOps — TEK-UP, ING-5-SSIR-S9-P3, 2026-2027 — Projet 2.

## Pipeline

```
Ingestion            Normalisation       Détection             Corrélation             Enrichissement        Rapport
PCAP (scapy)    ┐                        Règles YAML           succès après brute      VirusTotal v3         HTML + JSON
auth.log        ├──▶ Event (schéma  ──▶  fenêtre glissante ──▶ force, ports ouverts, ──▶ cache SQLite    ──▶  ATT&CK, Kill Chain,
EVTX / XML      ┘    commun, UTC)        par groupe            même source              mode hors ligne       preuves, SHA-256
```

| Étape | Module | Rôle |
|---|---|---|
| Ingestion | `pyhunter/ingest/` | `pcap.py` (SYN, SYN-ACK, requêtes DNS), `authlog.py` (syslog et RFC 3339), `evtx.py` (4624/4625, `.evtx` ou export XML `wevtutil`) |
| Normalisation | `pyhunter/models.py` | `Event` : `ts, source, kind, src_ip, dst_ip, ports, user, service, query, base_domain, raw` |
| Détection | `pyhunter/detection/` | chargement et validation des règles, moteur à fenêtre glissante, métriques |
| Corrélation | `detection/correlation.py` | compromission après brute force, ports ouverts du scan, campagnes par IP source |
| Enrichissement | `pyhunter/enrich/` | client VirusTotal (limitation de débit, reprises), cache SQLite avec durée de vie, mode hors ligne |
| Rapport | `pyhunter/report/` | `rapport.json` (source de vérité) et `rapport.html` (autonome, imprimable) |

## Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .                   # crée la commande « pyhunter »
```

Python 3.11 ou plus récent.

## Utilisation

```bash
# 1. Jeu de données synthétique (scénario complet, reproductible)
python scripts/generate_lab_data.py --out samples --seed 42

# 2. Analyse
pyhunter analyze --pcap samples/lab.pcap --authlog samples/auth.log \
                 --evtx samples/security.xml --year 2026 --offline -o rapport/

# Règles
pyhunter rules list
pyhunter rules validate -r rules/

# Cache d'enrichissement
pyhunter cache stats
pyhunter cache clear
```

Options de `analyze` :

| Option | Effet |
|---|---|
| `--pcap`, `--authlog`, `--evtx` | entrées, chacune répétable ; `--evtx` accepte `.evtx` ou un export `.xml` |
| `-r / --rules` | fichier ou dossier de règles (défaut : `rules/`) |
| `-o / --out` | dossier de sortie (`rapport.json` + `rapport.html`) |
| `--offline` | enrichissement uniquement depuis le cache local (démonstration sans réseau) |
| `--no-enrich` | aucun enrichissement |
| `--year`, `--tz` | année et fuseau des lignes syslog classiques, qui n'en contiennent pas (ex. `--tz Africa/Tunis`) |
| `-v`, `-vv` | journalisation détaillée |

### Clé VirusTotal

La clé n'est **jamais** écrite dans le code, les règles ni la configuration :

```bash
export VT_API_KEY="votre_clé"          # PowerShell : $env:VT_API_KEY = "votre_clé"
```

Sans clé, l'analyse fonctionne : les IOC sont simplement marqués « non configuré ».
L'API publique gratuite est limitée à 4 requêtes par minute ; l'outil espace donc
les appels de 15 s, refait jusqu'à 3 tentatives en cas d'erreur 429/5xx ou
d'expiration du délai, et met chaque réponse en cache 7 jours (y compris les « inconnu »).
Les IP privées et les domaines réservés (`.test`, `.lab`, `.local`…) ne sont jamais envoyés.

Configuration optionnelle : copier `config/pyhunter.example.yaml` en `./pyhunter.yaml`.

## Règles de détection (YAML, séparées du code)

| ID | Détection | Condition | Fenêtre | Sévérité | ATT&CK | Kill Chain |
|---|---|---|---|---|---|---|
| SCAN-001 | Scan de ports TCP SYN | `ports_distincts >= 20` par (source, cible) | 10 s | moyenne | T1046 | reconnaissance |
| BF-001 | Brute force SSH | `echecs_auth >= 10` | 60 s | haute | T1110.001, T1021.004 | exploitation |
| BF-002 | Brute force RDP / Windows (4625) | `echecs_auth >= 10`, type 10 ou 3 | 60 s | haute | T1110.001, T1021.001 | exploitation |
| BF-003 | Password spraying | `utilisateurs_distincts >= 8` | 10 min | haute | T1110.003 | exploitation |
| DNS-001 | DNS à forte entropie (tunnel) | `entropie_dns >= 3.5 et longueur_sous_domaine >= 20`, au moins 10 fois | 5 min | haute | T1071.004 | commande et contrôle |

Format (les clés de l'exemple de la fiche projet sont conservées) :

```yaml
- id: BF-001
  titre: Brute force SSH
  source: auth.log                 # pcap | auth.log | evtx | "*" | liste
  condition: echecs_auth >= 10     # clauses reliées par « et »
  fenetre: 60s
  severite: haute                  # faible | moyenne | haute | critique
  attack: [T1110.001, T1021.004]
  kill_chain: exploitation
  groupe_par: [src_ip]             # une fenêtre par IP source
  filtre: {service: ssh}           # optionnel
  exclure: {base_domain: [...]}    # optionnel (liste blanche, suffixe pour les domaines)
  ioc: [src_ip]                    # champs reportés comme IOC
  faux_positifs: ...               # documentation de la règle, reprise dans le rapport
  reponse: ...
```

Métriques disponibles : `occurrences`, `echecs_auth`, `succes_auth`,
`utilisateurs_distincts`, `ports_distincts`, `hotes_distincts` (agrégées sur la
fenêtre) et `entropie_dns`, `longueur_sous_domaine`, `longueur_requete_dns`
(calculées par événement). Les conditions sont lues par une grammaire stricte,
sans `eval` : une métrique inconnue, une clé mal orthographiée ou des métriques
incompatibles produisent une erreur explicite.

**Fonctionnement du moteur.** Pour chaque règle, les événements retenus sont
regroupés (par IP source par défaut). Chaque groupe garde une fenêtre glissante
de durée `fenetre`, avec des compteurs incrémentaux (O(1) par événement). Quand
la condition est vraie, un incident s'ouvre ; il absorbe les événements suivants
tant qu'ils arrivent à moins d'une fenêtre d'intervalle, puis devient **une**
alerte. On obtient une alerte par épisode d'attaque, pas une par paquet.

**Corrélation.**
- Une connexion réussie depuis l'IP d'un brute force (jusqu'à 30 min après) fait
  passer l'alerte en « critique », ajoute T1078 et la marque comme compromission probable.
- Les ports ayant répondu SYN-ACK pendant un scan sont listés comme ouverts.
- Une même IP source à l'origine de plusieurs règles forme une campagne,
  ordonnée selon la Kill Chain.
- Un IOC signalé malveillant par au moins 3 moteurs VirusTotal relève la sévérité d'un niveau.

## Tests

```bash
pytest -q        # 75 tests
```

Les tests couvrent les analyseurs (formats, fuseaux, changement d'année,
`message repeated`, export `wevtutil`), la validation des règles, les seuils et
fenêtres (juste au-dessous, juste au-dessus, tentatives trop lentes, groupes
indépendants), la liste blanche DNS, la corrélation et le cache (hors ligne,
expiration, reprises, API indisponible, limitation de débit). Ils vérifient
aussi l'échappement HTML, car un nom d'utilisateur `<script>` injecté dans un
journal ne doit pas s'exécuter dans le rapport. Enfin, un test de bout en bout
s'exécute sur le scénario du laboratoire.

## Contraintes respectées

- Données synthétiques ou captures de laboratoire uniquement : aucun trafic réel.
- Règles YAML séparées du code.
- Enrichissement d'IOC avec cache local et mode hors ligne.
- Rapport HTML/JSON avec correspondance MITRE ATT&CK, et empreinte SHA-256 de chaque fichier analysé.

## Arborescence

```
pyhunter/        code (ingest/, detection/, enrich/, report/, pipeline.py, cli.py)
rules/           règles de détection YAML
config/          configuration d'exemple
scripts/         générateur du jeu de données de laboratoire
samples/         jeu de données généré + SCENARIO.md
exemple_rapport/ rapport produit sur le scénario
tests/           pytest
```
