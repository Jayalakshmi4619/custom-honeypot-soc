import os
import sys


# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

PROJECT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_DIR)


from database.database import get_connection


# ---------------------------------------------------------
# BASIC STATISTICS
# ---------------------------------------------------------

def get_total_events():

    connection = get_connection()

    row = connection.execute(
        "SELECT COUNT(*) AS total FROM events"
    ).fetchone()

    connection.close()

    return row["total"]


def get_total_alerts():

    connection = get_connection()

    row = connection.execute(
        "SELECT COUNT(*) AS total FROM alerts"
    ).fetchone()

    connection.close()

    return row["total"]


def get_unique_attackers():

    connection = get_connection()

    row = connection.execute(
        """
        SELECT COUNT(DISTINCT source_ip) AS total
        FROM events
        WHERE source_ip IS NOT NULL
        """
    ).fetchone()

    connection.close()

    return row["total"]


# ---------------------------------------------------------
# SERVICE STATISTICS
# ---------------------------------------------------------

def get_service_statistics():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            COALESCE(service, 'SSH') AS service,
            COUNT(*) AS total
        FROM events
        GROUP BY COALESCE(service, 'SSH')
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["service"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# SEVERITY STATISTICS
# ---------------------------------------------------------

def get_severity_distribution():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            COALESCE(severity, 'unknown') AS severity,
            COUNT(*) AS total
        FROM events
        GROUP BY COALESCE(severity, 'unknown')
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["severity"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# EVENT TYPE STATISTICS
# ---------------------------------------------------------

def get_event_type_statistics():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            event_type,
            COUNT(*) AS total
        FROM events
        GROUP BY event_type
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["event_type"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# HTTP PATH STATISTICS
# ---------------------------------------------------------

def get_http_path_statistics():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            request_path,
            COUNT(*) AS total
        FROM events
        WHERE service = 'HTTP'
        AND request_path IS NOT NULL
        GROUP BY request_path
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["request_path"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# TOP ATTACKERS
# ---------------------------------------------------------

def get_top_attackers(limit=5):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            source_ip,
            COUNT(*) AS attempts
        FROM events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY attempts DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    return [
        {
            "source_ip": row["source_ip"],
            "attempts": row["attempts"]
        }
        for row in rows
    ]


# ---------------------------------------------------------
# ALERT TYPE STATISTICS
# ---------------------------------------------------------

def get_alert_type_statistics():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            alert_type,
            COUNT(*) AS total
        FROM alerts
        GROUP BY alert_type
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["alert_type"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# ALERT SEVERITY STATISTICS
# ---------------------------------------------------------

def get_alert_severity_statistics():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            severity,
            COUNT(*) AS total
        FROM alerts
        GROUP BY severity
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["severity"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# ALERT SERVICE STATISTICS
# ---------------------------------------------------------

def get_alert_service_statistics():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            service,
            COUNT(*) AS total
        FROM alerts
        GROUP BY service
        ORDER BY total DESC
        """
    ).fetchall()

    connection.close()

    return {
        row["service"]: row["total"]
        for row in rows
    }


# ---------------------------------------------------------
# COMBINE ALL STATISTICS
# ---------------------------------------------------------

def get_honeypot_statistics():

    return {
        "total_events":
            get_total_events(),

        "total_alerts":
            get_total_alerts(),

        "unique_attackers":
            get_unique_attackers(),

        "services":
            get_service_statistics(),

        "severity_distribution":
            get_severity_distribution(),

        "event_types":
            get_event_type_statistics(),

        "http_paths":
            get_http_path_statistics(),

        "alert_types":
            get_alert_type_statistics(),

        "alert_severity":
            get_alert_severity_statistics(),

        "alert_services":
            get_alert_service_statistics(),

        "top_attackers":
            get_top_attackers()
    }


# ---------------------------------------------------------
# DISPLAY STATISTICS
# ---------------------------------------------------------

def display_statistics():

    statistics = get_honeypot_statistics()

    print("\n" + "=" * 60)
    print("         HONEYPOT STATISTICS")
    print("=" * 60)

    print(
        f"\nTotal Events: "
        f"{statistics['total_events']}"
    )

    print(
        f"Total Alerts: "
        f"{statistics['total_alerts']}"
    )

    print(
        f"Unique Attackers: "
        f"{statistics['unique_attackers']}"
    )

    print("\nService Statistics:")

    for service, count in statistics["services"].items():

        print(f"  {service}: {count}")

    print("\nSeverity Distribution:")

    for severity, count in (
        statistics["severity_distribution"].items()
    ):

        print(f"  {severity}: {count}")

    print("\nEvent Type Statistics:")

    for event_type, count in (
        statistics["event_types"].items()
    ):

        print(f"  {event_type}: {count}")

    print("\nHTTP Path Statistics:")

    for path, count in (
        statistics["http_paths"].items()
    ):

        print(f"  {path}: {count}")

    print("\nAlert Type Statistics:")

    for alert_type, count in (
        statistics["alert_types"].items()
    ):

        print(f"  {alert_type}: {count}")

    print("\nAlert Severity Statistics:")

    for severity, count in (
        statistics["alert_severity"].items()
    ):

        print(f"  {severity}: {count}")

    print("\nAlert Service Statistics:")

    for service, count in (
        statistics["alert_services"].items()
    ):

        print(f"  {service}: {count}")

    print("\nTop Attackers:")

    for attacker in statistics["top_attackers"]:

        print(
            f"  {attacker['source_ip']} "
            f"→ {attacker['attempts']} events"
        )

    print("\n" + "=" * 60)


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    display_statistics()
