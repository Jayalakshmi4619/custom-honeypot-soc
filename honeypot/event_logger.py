import json
import os
import sys
from datetime import datetime, timezone


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
# LOG FILE
# ---------------------------------------------------------

LOG_DIR = os.path.join(
    PROJECT_DIR,
    "logs"
)

LOG_FILE = os.path.join(
    LOG_DIR,
    "honeypot_events.jsonl"
)


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

from database.database import (
    initialize_database,
    insert_event
)


# ---------------------------------------------------------
# EVENT LOGGER
# ---------------------------------------------------------

def log_event(
    event_type,
    source_ip="unknown",
    source_port=None,
    destination_port=None,
    username=None,
    password=None,
    protocol=None,
    severity="low",
    details=None,
    service=None,
    attack_type=None,
    status=None,
    request_method=None,
    request_path=None,
    user_agent=None,
    session_id=None
):

    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )


    # -----------------------------------------------------
    # SAFE CREDENTIAL HANDLING
    # -----------------------------------------------------

    # We do NOT store submitted passwords.
    # This protects credentials while still recording
    # that an authentication attempt occurred.

    password_present = (
        password is not None
    )


    # -----------------------------------------------------
    # EVENT
    # -----------------------------------------------------

    event = {

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "event_type":
            event_type,

        "service":
            service,

        "source_ip":
            source_ip,

        "source_port":
            source_port,

        "destination_port":
            destination_port,

        "protocol":
            protocol,

        "username":
            username,

        "attack_type":
            attack_type,

        "severity":
            severity,

        "status":
            status,

        "request_method":
            request_method,

        "request_path":
            request_path,

        "user_agent":
            user_agent,

        "session_id":
            session_id,

        "details":
            details or {},

        "password_present":
            password_present
    }


    # -----------------------------------------------------
    # WRITE JSONL
    # -----------------------------------------------------

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(event) + "\n"
        )


    # -----------------------------------------------------
    # PREPARE DATABASE EVENT
    # -----------------------------------------------------

    database_event = {

        "timestamp":
            event["timestamp"],

        "event_type":
            event["event_type"],

        "service":
            event["service"],

        "source_ip":
            event["source_ip"],

        "source_port":
            event["source_port"],

        "destination_port":
            event["destination_port"],

        "protocol":
            event["protocol"],

        "username":
            event["username"],

        "attack_type":
            event["attack_type"],

        "severity":
            event["severity"],

        "status":
            event["status"],

        "request_method":
            event["request_method"],

        "request_path":
            event["request_path"],

        "user_agent":
            event["user_agent"],

        "session_id":
            event["session_id"],

        "details":
            json.dumps(
                event["details"]
            )
    }


    # -----------------------------------------------------
    # WRITE DATABASE
    # -----------------------------------------------------

    try:

        insert_event(
            database_event
        )

    except Exception as error:

        print(
            f"[DATABASE ERROR] {error}"
        )


    return event


# ---------------------------------------------------------
# TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    initialize_database()


    test_event = log_event(

        event_type="logger_test",

        source_ip="127.0.0.1",

        destination_port=2222,

        protocol="TCP",

        severity="low",

        service="SSH",

        details={
            "message":
                "Event logger database test"
        }
    )


    print(
        json.dumps(
            test_event,
            indent=4
        )
    )


    print(
        f"\nJSONL saved to:"
        f"\n{LOG_FILE}"
    )
