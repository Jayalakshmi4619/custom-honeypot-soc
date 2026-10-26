import os
import sqlite3
from datetime import datetime, timezone


PROJECT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_DIR = os.path.join(
    PROJECT_DIR,
    "database"
)

DATABASE_FILE = os.path.join(
    DATABASE_DIR,
    "honeypot.db"
)


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_connection():
    """Create a connection to the honeypot database."""

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    connection.row_factory = sqlite3.Row

    return connection


# ---------------------------------------------------------
# INITIALIZE DATABASE
# ---------------------------------------------------------

def initialize_database():
    """Create and update all required honeypot tables."""

    connection = get_connection()

    cursor = connection.cursor()

    # -----------------------------------------------------
    # EVENTS TABLE
    # -----------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            event_type TEXT NOT NULL,

            service TEXT,

            source_ip TEXT,

            source_port INTEGER,

            destination_port INTEGER,

            protocol TEXT,

            username TEXT,

            attack_type TEXT,

            severity TEXT,

            status TEXT,

            request_method TEXT,

            request_path TEXT,

            user_agent TEXT,

            session_id TEXT,

            details TEXT
        )
        """
    )

    # -----------------------------------------------------
    # ALERTS TABLE
    # -----------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            alert_type TEXT NOT NULL,

            source_ip TEXT,

            service TEXT,

            severity TEXT,

            event_count INTEGER,

            description TEXT,

            status TEXT DEFAULT 'new',

            mitre_technique_id TEXT,

            mitre_technique_name TEXT,

            mitre_tactic TEXT
        )
        """
    )

    # -----------------------------------------------------
    # UPDATE EXISTING ALERTS TABLE
    # -----------------------------------------------------

    cursor.execute(
        "PRAGMA table_info(alerts)"
    )

    existing_columns = {
        row["name"]
        for row in cursor.fetchall()
    }

    mitre_columns = {
        "mitre_technique_id": "TEXT",
        "mitre_technique_name": "TEXT",
        "mitre_tactic": "TEXT"
    }

    for column_name, column_type in mitre_columns.items():

        if column_name not in existing_columns:

            cursor.execute(
                f"""
                ALTER TABLE alerts
                ADD COLUMN {column_name} {column_type}
                """
            )

            print(
                f"[+] Added column: {column_name}"
            )

    connection.commit()

    connection.close()


# ---------------------------------------------------------
# INSERT EVENT
# ---------------------------------------------------------

def insert_event(event):
    """Insert a honeypot event into the database."""

    connection = get_connection()

    cursor = connection.cursor()

    timestamp = event.get(
        "timestamp"
    )

    if not timestamp:

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

    cursor.execute(
        """
        INSERT INTO events (
            timestamp,
            event_type,
            service,
            source_ip,
            source_port,
            destination_port,
            protocol,
            username,
            attack_type,
            severity,
            status,
            request_method,
            request_path,
            user_agent,
            session_id,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            event.get("event_type"),
            event.get("service"),
            event.get("source_ip"),
            event.get("source_port"),
            event.get("destination_port"),
            event.get("protocol"),
            event.get("username"),
            event.get("attack_type"),
            event.get("severity"),
            event.get("status"),
            event.get("request_method"),
            event.get("request_path"),
            event.get("user_agent"),
            event.get("session_id"),
            event.get("details")
        )
    )

    connection.commit()

    event_id = cursor.lastrowid

    connection.close()

    return event_id


# ---------------------------------------------------------
# INSERT ALERT
# ---------------------------------------------------------

def insert_alert(
    alert_type,
    source_ip,
    service,
    severity,
    event_count,
    description,
    mitre_technique_id=None,
    mitre_technique_name=None,
    mitre_tactic=None
):
    """Store a detected security alert."""

    connection = get_connection()

    cursor = connection.cursor()

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    cursor.execute(
        """
        INSERT INTO alerts (
            timestamp,
            alert_type,
            source_ip,
            service,
            severity,
            event_count,
            description,
            mitre_technique_id,
            mitre_technique_name,
            mitre_tactic
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            alert_type,
            source_ip,
            service,
            severity,
            event_count,
            description,
            mitre_technique_id,
            mitre_technique_name,
            mitre_tactic
        )
    )

    connection.commit()

    alert_id = cursor.lastrowid

    connection.close()

    return alert_id


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    initialize_database()

    print("=" * 60)
    print("       HONEYPOT DATABASE")
    print("=" * 60)

    print(
        f"Database: {DATABASE_FILE}"
    )

    print("\nTables:")

    print("  - events")

    print("  - alerts")

    print("\nMITRE ATT&CK columns:")

    print("  - mitre_technique_id")

    print("  - mitre_technique_name")

    print("  - mitre_tactic")

    print("\nStatus: READY")

    print("=" * 60)
