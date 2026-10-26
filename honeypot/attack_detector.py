
import json
import os
import sys
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

PROJECT_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
sys.path.insert(0, PROJECT_DIR)

from database.database import get_connection, insert_alert


# ---------------------------------------------------------
# DETECTION SETTINGS
# ---------------------------------------------------------

BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW_MINUTES = 3

SSH_COMMAND_THRESHOLD = 3
SSH_COMMAND_WINDOW_MINUTES = 5


# ---------------------------------------------------------
# MITRE ATT&CK MAPPING
# ---------------------------------------------------------

MITRE_ATTACK_MAPPING = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "suspicious_path_access": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "ssh_suspicious_commands": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
}


# ---------------------------------------------------------
# GET RECENT AUTHENTICATION ATTEMPTS
# ---------------------------------------------------------

def get_recent_auth_attempts(source_ip, service):

    connection = get_connection()

    cutoff_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    ).isoformat()

    event_type = (
        "ssh_auth_attempt"
        if service == "SSH"
        else "http_login_attempt"
    )

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE event_type = ?
              AND source_ip = ?
              AND timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (event_type, source_ip, cutoff_time),
        ).fetchall()
    finally:
        connection.close()

    return rows


# ---------------------------------------------------------
# DETECT BRUTE FORCE
# ---------------------------------------------------------

def detect_brute_force(source_ip, service):

    attempts = get_recent_auth_attempts(
        source_ip,
        service
    )

    attempt_count = len(attempts)

    if attempt_count >= BRUTE_FORCE_THRESHOLD:

        mitre_info = MITRE_ATTACK_MAPPING["brute_force"]

        return {
            "detected": True,
            "attack_type": "brute_force",
            "severity": "high",
            "source_ip": source_ip,
            "service": service,
            "attempt_count": attempt_count,
            "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "mitre_tactic": mitre_info["tactic"],
        }

    return {
        "detected": False,
        "source_ip": source_ip,
        "service": service,
        "attempt_count": attempt_count,
    }


# ---------------------------------------------------------
# DETECT SUSPICIOUS HTTP PATHS
# ---------------------------------------------------------

def detect_suspicious_paths():

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE event_type = 'http_suspicious_path'
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    results = []
    mitre_info = MITRE_ATTACK_MAPPING["suspicious_path_access"]

    for row in rows:

        results.append({
            "detected": True,
            "attack_type": "suspicious_path_access",
            "severity": "medium",
            "source_ip": row["source_ip"],
            "service": "HTTP",
            "request_path": row["request_path"],
            "event_id": row["id"],
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "mitre_tactic": mitre_info["tactic"],
        })

    return results


# ---------------------------------------------------------
# DETECT SUSPICIOUS SSH COMMAND ACTIVITY
# ---------------------------------------------------------

def detect_suspicious_ssh_commands():

    cutoff_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=SSH_COMMAND_WINDOW_MINUTES)
    ).isoformat()

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE event_type = 'ssh_command'
              AND timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (cutoff_time,),
        ).fetchall()
    finally:
        connection.close()

    grouped_events = {}

    for row in rows:

        try:
            details_value = row["details"]

            details = (
                json.loads(details_value)
                if details_value
                else {}
            )

        except (json.JSONDecodeError, TypeError):
            continue

        if details.get("suspicious") is not True:
            continue

        source_ip = row["source_ip"] or "unknown"
        session_id = row["session_id"] or "unknown-session"

        group_key = (source_ip, session_id)

        grouped_events.setdefault(
            group_key,
            []
        ).append({
            "command": details.get("command", ""),
            "category": details.get(
                "command_category",
                "unknown"
            ),
            "severity": row["severity"] or "medium",
        })

    results = []

    mitre_info = MITRE_ATTACK_MAPPING[
        "ssh_suspicious_commands"
    ]

    for (source_ip, session_id), events in grouped_events.items():

        if len(events) < SSH_COMMAND_THRESHOLD:
            continue

        categories = sorted({
            event["category"]
            for event in events
        })

        commands = [
            event["command"]
            for event in events
        ]

        result = {
            "detected": True,
            "attack_type": "ssh_suspicious_commands",
            "severity": "medium",
            "source_ip": source_ip,
            "service": "SSH",
            "attempt_count": len(events),
            "categories": categories,
            "commands": commands,
            "session_id": session_id,
            "window_minutes": SSH_COMMAND_WINDOW_MINUTES,
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_technique_name": mitre_info["technique_name"],
            "mitre_tactic": mitre_info["tactic"],
        }

        results.append(result)

    return results


# ---------------------------------------------------------
# CHECK IF ALERT ALREADY EXISTS
# ---------------------------------------------------------

def alert_already_exists(source_ip, alert_type, service):

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT id
            FROM alerts
            WHERE source_ip = ?
              AND alert_type = ?
              AND service = ?
            LIMIT 1
            """,
            (source_ip, alert_type, service),
        ).fetchone()
    finally:
        connection.close()

    return row is not None


# ---------------------------------------------------------
# CREATE ALERT
# ---------------------------------------------------------

def create_alert(result):

    source_ip = result["source_ip"]
    alert_type = result["attack_type"]
    service = result["service"]

    if alert_already_exists(
        source_ip,
        alert_type,
        service
    ):

        print(
            f"\n[!] Alert already exists for {service} "
            f"{alert_type} from {source_ip}."
        )

        return

    if alert_type == "brute_force":

        description = (
            f"Detected {result['attempt_count']} failed "
            f"{service} authentication attempts from "
            f"{source_ip} within "
            f"{result['window_minutes']} minutes. "
            f"MITRE ATT&CK: "
            f"{result['mitre_technique_id']} - "
            f"{result['mitre_technique_name']}."
        )

    elif alert_type == "suspicious_path_access":

        description = (
            f"Suspicious HTTP path access detected from "
            f"{source_ip}. Requested path: "
            f"{result.get('request_path', 'unknown')}. "
            f"MITRE ATT&CK: "
            f"{result['mitre_technique_id']} - "
            f"{result['mitre_technique_name']}."
        )

    elif alert_type == "ssh_suspicious_commands":

        description = (
            f"Detected {result['attempt_count']} suspicious "
            f"SSH commands from {source_ip} within "
            f"{result['window_minutes']} minutes. "
            f"Categories: "
            f"{', '.join(result.get('categories', []))}. "
            f"Commands: "
            f"{'; '.join(result.get('commands', []))}. "
            f"MITRE ATT&CK: "
            f"{result['mitre_technique_id']} - "
            f"{result['mitre_technique_name']}."
        )

    else:
        description = "Security event detected."

    alert_id = insert_alert(
        alert_type=alert_type,
        source_ip=source_ip,
        service=service,
        severity=result["severity"],
        event_count=result.get("attempt_count", 1),
        description=description,
        mitre_technique_id=result["mitre_technique_id"],
        mitre_technique_name=result["mitre_technique_name"],
        mitre_tactic=result["mitre_tactic"],
    )

    print("\n[+] Alert created successfully!")
    print(f"    Alert ID: {alert_id}")


# ---------------------------------------------------------
# ANALYZE AUTHENTICATION EVENTS
# ---------------------------------------------------------

def analyze_authentication_events():

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT DISTINCT source_ip, service
            FROM events
            WHERE event_type IN (
                'ssh_auth_attempt',
                'http_login_attempt'
            )
            """
        ).fetchall()
    finally:
        connection.close()

    results = []

    for row in rows:

        result = detect_brute_force(
            row["source_ip"],
            row["service"]
        )

        results.append(result)

        if result["detected"]:
            create_alert(result)

    return results


# ---------------------------------------------------------
# ANALYZE ALL EVENTS
# ---------------------------------------------------------

def analyze_latest_events():

    results = []

    # 1. Authentication analysis
    auth_results = analyze_authentication_events()
    results.extend(auth_results)

    # 2. Suspicious HTTP path analysis
    path_results = detect_suspicious_paths()

    for result in path_results:
        results.append(result)
        create_alert(result)

    # 3. Suspicious SSH command analysis
    ssh_results = detect_suspicious_ssh_commands()

    for result in ssh_results:
        results.append(result)
        create_alert(result)

    return results


# ---------------------------------------------------------
# DISPLAY RESULTS
# ---------------------------------------------------------

def display_results(results):

    print("\n" + "=" * 65)
    print("                 ATTACK DETECTION ENGINE")
    print("=" * 65)

    if not results:
        print("No events found.")
        return

    for result in results:

        print(
            f"\nService   : "
            f"{result.get('service', 'Unknown')}"
        )

        print(
            f"Source IP : "
            f"{result.get('source_ip', 'Unknown')}"
        )

        if "attempt_count" in result:
            print(
                f"Count     : "
                f"{result['attempt_count']}"
            )

        if "request_path" in result:
            print(
                f"Path      : "
                f"{result['request_path']}"
            )

        if result.get("detected"):

            print("\n[!] SECURITY ACTIVITY DETECTED")

            print(
                f"Type      : "
                f"{result.get('attack_type', 'Unknown')}"
            )

            print(
                f"Severity  : "
                f"{result.get('severity', 'Unknown')}"
            )

            print(
                f"MITRE     : "
                f"{result.get('mitre_technique_id', 'N/A')} - "
                f"{result.get('mitre_technique_name', 'N/A')}"
            )

            print(
                f"Tactic    : "
                f"{result.get('mitre_tactic', 'N/A')}"
            )

            if result.get("categories"):
                print(
                    f"Categories: "
                    f"{', '.join(result['categories'])}"
                )

        elif "attempt_count" in result:
            print("Status    : Below brute-force threshold")

    print("\n" + "=" * 65)


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    results = analyze_latest_events()

    display_results(results)
