import os
import sys

from flask import Flask, jsonify
from flask_cors import CORS


# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

PROJECT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_DIR)


# ---------------------------------------------------------
# IMPORT PROJECT MODULES
# ---------------------------------------------------------

from database.database import get_connection
from honeypot_statistics.statistics_engine import get_honeypot_statistics


# ---------------------------------------------------------
# FLASK APPLICATION
# ---------------------------------------------------------

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def home():

    return jsonify(
        {
            "message": "Custom Honeypot API is running",
            "status": "online"
        }
    )


# ---------------------------------------------------------
# HONEYPOT STATISTICS
# ---------------------------------------------------------

@app.route("/api/statistics")
def statistics():

    data = get_honeypot_statistics()

    return jsonify(data)


# ---------------------------------------------------------
# RECENT EVENTS
# ---------------------------------------------------------

@app.route("/api/events")
def events():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    connection.close()

    events_data = [
        dict(row)
        for row in rows
    ]

    return jsonify(events_data)


# ---------------------------------------------------------
# ALERTS
# ---------------------------------------------------------

@app.route("/api/alerts")
def alerts():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    connection.close()

    alerts_data = [
        dict(row)
        for row in rows
    ]

    return jsonify(alerts_data)
# ---------------------------------------------------------
# UPDATE ALERT STATUS
# ---------------------------------------------------------

@app.route("/api/alerts/<int:alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):

    from flask import request

    allowed_statuses = {
        "new",
        "in_progress",
        "investigated",
        "closed"
    }

    data = request.get_json(silent=True) or {}
    new_status = data.get("status")

    if new_status not in allowed_statuses:
        return jsonify({
            "error": "Invalid status",
            "allowed_statuses": sorted(allowed_statuses)
        }), 400

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = ?
            WHERE id = ?
            """,
            (new_status, alert_id)
        )

        if cursor.rowcount == 0:
            connection.rollback()
            return jsonify({
                "error": "Alert not found",
                "alert_id": alert_id
            }), 404

        connection.commit()

        row = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

        return jsonify({
            "message": "Alert status updated successfully",
            "alert": dict(row)
        })

    except Exception:
        connection.rollback()
        app.logger.exception("Failed to update alert status")
        return jsonify({
            "error": "Failed to update alert status"
        }), 500

    finally:
        connection.close()

# ---------------------------------------------------------
# RUN SERVER
# ---------------------------------------------------------

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("          CUSTOM HONEYPOT API SERVER")
    print("=" * 60)

    print("\nServer: http://127.0.0.1:5000")
    print("Status: RUNNING")

    print("\nAvailable Endpoints:")
    print("  /")
    print("  /api/statistics")
    print("  /api/events")
    print("  /api/alerts")

    print("\n" + "=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
