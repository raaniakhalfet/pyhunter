# Scénario du laboratoire (données synthétiques)

Généré par `python scripts/generate_lab_data.py --out samples --seed 42`. Avec la
même graine, le générateur produit exactement les mêmes fichiers. Tous les
horodatages sont en UTC, le 20/11/2026.

## Réseau

| Hôte | IP | Rôle |
|---|---|---|
| attaquant | 192.168.56.10 | machine de l'attaquant |
| srv-web | 192.168.56.20 | serveur Linux exposé (SSH 22, HTTP 80, HTTPS 443) |
| PC-RH-07 | 192.168.56.40 | poste Windows du service RH |
| poste utilisateur | 192.168.56.50 | navigation normale (bruit de fond) |
| ADMIN-PC | 192.168.56.1 | administrateur légitime |
| résolveur DNS | 192.168.56.2 | résolveur interne |

## Déroulé de l'attaque

| Heure | Étape | Source | Kill Chain | ATT&CK | Règle attendue |
|---|---|---|---|---|---|
| 09:02:00 | Scan SYN des ports 1 à 1024 de srv-web (22, 80 et 443 ouverts) | `lab.pcap` | Reconnaissance | T1046 | SCAN-001 |
| 09:03:10 | Brute force SSH sur root, admin, oracle, webadmin (27 échecs) | `auth.log` | Exploitation | T1110.001 | BF-001 |
| 09:03:54 | Connexion réussie « webadmin » depuis l'attaquant | `auth.log` | Installation | T1078 | corrélation : critique |
| 09:06:00 | Tunnel DNS depuis srv-web : 40 requêtes TXT encodées en base32 vers `*.t.exfil-lab.test` | `lab.pcap` | Commande et contrôle | T1071.004 | DNS-001 |
| 09:10:00 | Brute force RDP de srv-web vers PC-RH-07 (15 événements 4625, type 10) : mouvement latéral | `security.xml` | Exploitation | T1110.001, T1021.001 | BF-002 |

## Activité légitime (contrôle des faux positifs)

Aucune de ces activités ne doit déclencher d'alerte :
- requêtes DNS et connexions HTTPS normales depuis le poste utilisateur et srv-web, pendant 30 minutes ;
- l'administrateur se trompe une fois de mot de passe SSH, puis se connecte (08:58) ;
- une connexion RDP légitime de l'administrateur (4624, 08:45) ;
- une faute de frappe locale sur PC-RH-07 (4625, type 2, sans IP).

## Points d'investigation à exploiter dans le rapport

- **Pivot.** srv-web (192.168.56.20) est la **victime** du brute force SSH, puis devient
  la **source** du tunnel DNS et du brute force RDP. C'est la preuve d'une compromission
  suivie d'un mouvement latéral. L'outil corrèle par IP source ; c'est l'analyste qui
  fait le lien entre l'hôte `srv-web` du journal et l'IP 192.168.56.20 du PCAP.
- **Faux positifs.** Les règles BF-001 et BF-002 ne se déclenchent pas sur l'erreur
  isolée de l'administrateur : il faut au moins 10 échecs en 60 secondes.

## Reproduire avec de vraies VM (laboratoire isolé)

Sur un réseau VirtualBox « host-only » isolé, sans accès Internet :

```bash
# victime :
sudo tcpdump -i enp0s8 -w lab.pcap
# attaquant :
nmap -sS -p1-1024 192.168.56.20
hydra -L users.txt -P mots_de_passe.txt ssh://192.168.56.20 -t 4
# victime : copier /var/log/auth.log
# Windows : wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:xml > security.xml
```

Avec l'authentification au niveau du réseau (NLA), les échecs RDP apparaissent en
type d'ouverture 3, et non 10. C'est pourquoi BF-002 accepte les deux.
