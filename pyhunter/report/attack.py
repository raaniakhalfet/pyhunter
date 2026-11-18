"""Local MITRE ATT&CK (Enterprise) reference for the techniques used by the rules.

Kept offline on purpose (the tool must run without network). Add a line here
when a new rule references a technique that is not listed.
"""

from __future__ import annotations

TECHNIQUES: dict[str, tuple[str, str]] = {
    # id: (name, tactic)
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.001": ("Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration"),
}

KILL_CHAIN_LABELS = {
    "reconnaissance": "1. Reconnaissance",
    "armement": "2. Armement",
    "livraison": "3. Livraison",
    "exploitation": "4. Exploitation",
    "installation": "5. Installation",
    "commande_controle": "6. Commande et contrôle",
    "actions_objectifs": "7. Actions sur objectifs",
}


def technique(tid: str) -> dict[str, str]:
    name, tactic = TECHNIQUES.get(tid, ("Technique non référencée localement", "?"))
    return {
        "id": tid,
        "nom": name,
        "tactique": tactic,
        "lien": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
    }
