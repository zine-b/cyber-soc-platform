import re

# transformer les logs bruts en événements structurés.
def parse_linux_auth_log(message: str):
    """
    Parser simple pour les logs SSH Linux.
    Détecte plusieurs formats d'échecs de connexion SSH.
    """

    failed_login_patterns = [
        re.compile(
            r"Failed password for (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
        re.compile(
            r"Invalid password for user (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
        re.compile(
            r"Authentication failed for (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
        re.compile(
            r"Login failed user=(?P<username>\w+) src=(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
    ]

    for pattern in failed_login_patterns:
        match = pattern.search(message)

        if match:
            return {
                "category": "authentication",
                "action": "login_failed",
                "username": match.group("username"),
                "source_ip": match.group("source_ip"),
                "severity": "medium"
            }

    return {
        "category": "unknown",
        "action": "unknown",
        "username": None,
        "source_ip": None,
        "severity": "low"
    }