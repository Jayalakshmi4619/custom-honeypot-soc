import os
import sys

from flask import Flask, render_template


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
# FLASK APPLICATION
# ---------------------------------------------------------

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)


# ---------------------------------------------------------
# DASHBOARD HOME
# ---------------------------------------------------------

@app.route("/")
def dashboard():

    return render_template(
        "index.html"
    )
@app.route("/preview")
def dashboard_preview():
    return render_template("index_working.html")

# ---------------------------------------------------------
@app.route("/advanced")
def dashboard_advanced():
    return render_template("index_advanced.html")

# RUN DASHBOARD SERVER
# ---------------------------------------------------------

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("        HONEYPOT DASHBOARD SERVER")
    print("=" * 60)

    print(
        "\nDashboard: "
        "http://127.0.0.1:5001"
    )

    print(
        "Status: RUNNING"
    )

    print("\n" + "=" * 60)

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )
