import os
import sys

from flask import Flask, jsonify, render_template, request

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from database.database import get_connection
from honeypot_statistics.statistics_engine import get_honeypot_statistics

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_DIR, "dashboard", "templates")
)


@app.route("/")
def dashboard():
    return render_template("index_deploy.html")


@app.route("/health")
def health():
    return jsonify({"status": "online"})


@app.route("/api/statistics")
def statistics():
    return jsonify(get_honeypot_statistics())


@app.route("/api/events")
def events():
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 50"
        ).fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        connection.close()


@app.route("/api/alerts")
def alerts():
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 50"
        ).fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        connection.close()


@app.route("/api/alerts/<int:alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):
    allowed_statuses = {"new", "in_progress", "investigated", "closed"}
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
            "UPDATE alerts SET status = ? WHERE id = ?",
            (new_status, alert_id)
        )

        if cursor.rowcount == 0:
            connection.rollback()
            return jsonify({"error": "Alert not found"}), 404

        connection.commit()
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()

        return jsonify({
            "message": "Alert status updated successfully",
            "alert": dict(row)
        })
    except Exception:
        connection.rollback()
        app.logger.exception("Failed to update alert status")
        return jsonify({"error": "Failed to update alert status"}), 500
    finally:
        connection.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
