from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import sys
import uuid
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

PROJECT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_DIR)


from honeypot.event_logger import log_event


# ---------------------------------------------------------
# SERVER SETTINGS
# ---------------------------------------------------------

HOST = "0.0.0.0"
PORT = 8080


# ---------------------------------------------------------
# SUSPICIOUS PATHS
# ---------------------------------------------------------

SUSPICIOUS_PATHS = [

    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/config",
    "/login.php"

]


class HoneypotHTTPHandler(BaseHTTPRequestHandler):


    # -----------------------------------------------------
    # DISABLE DEFAULT HTTP LOGGING
    # -----------------------------------------------------

    def log_message(self, format, *args):
        pass


    # -----------------------------------------------------
    # RECORD HTTP REQUEST
    # -----------------------------------------------------

    def record_request(self):

        source_ip = self.client_address[0]
        source_port = self.client_address[1]

        parsed = urlparse(self.path)

        session_id = str(uuid.uuid4())

        user_agent = self.headers.get(
            "User-Agent",
            "unknown"
        )


        # -------------------------------------------------
        # NORMAL HTTP REQUEST EVENT
        # -------------------------------------------------

        log_event(

            event_type="http_request",

            source_ip=source_ip,

            source_port=source_port,

            destination_port=PORT,

            protocol="HTTP",

            service="HTTP",

            severity="medium",

            status="received",

            request_method=self.command,

            request_path=parsed.path,

            user_agent=user_agent,

            session_id=session_id,

            details={
                "query": parsed.query
            }

        )


        print(

            f"[HTTP] {source_ip}:{source_port} "
            f"{self.command} {parsed.path}"

        )


        # -------------------------------------------------
        # SUSPICIOUS PATH DETECTION
        # -------------------------------------------------

        if parsed.path.lower() in SUSPICIOUS_PATHS:

            log_event(

                event_type="http_suspicious_path",

                source_ip=source_ip,

                source_port=source_port,

                destination_port=PORT,

                protocol="HTTP",

                service="HTTP",

                attack_type=
                    "suspicious_path_access",

                severity="medium",

                status="detected",

                request_method=self.command,

                request_path=parsed.path,

                user_agent=user_agent,

                session_id=session_id,

                details={

                    "reason":
                        "Access to suspicious path"

                }

            )


            print(

                f"[SUSPICIOUS PATH] "
                f"{source_ip}:{source_port} "
                f"{self.command} "
                f"{parsed.path}"

            )


        return session_id


    # -----------------------------------------------------
    # SEND RESPONSE PAGE
    # -----------------------------------------------------

    def send_response_page(
        self,
        status_code,
        title,
        message
    ):

        body = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
</head>
<body>

    <h1>{title}</h1>

    <p>{message}</p>

    <hr>

    <h3>Internal Application</h3>

    <form method="POST" action="/login">

        <label>Username:</label>
        <input type="text" name="username">

        <br><br>

        <label>Password:</label>
        <input type="password" name="password">

        <br><br>

        <button type="submit">
            Login
        </button>

    </form>

</body>
</html>
"""

        body = body.encode(
            "utf-8"
        )


        self.send_response(
            status_code
        )


        self.send_header(

            "Content-Type",

            "text/html"

        )


        self.send_header(

            "Content-Length",

            str(len(body))

        )


        self.end_headers()

        self.wfile.write(
            body
        )


    # -----------------------------------------------------
    # HANDLE GET REQUEST
    # -----------------------------------------------------

    def do_GET(self):

        self.record_request()


        self.send_response_page(

            200,

            "Internal Application",

            "Welcome to the internal application."

        )


    # -----------------------------------------------------
    # HANDLE POST REQUEST
    # -----------------------------------------------------

    def do_POST(self):

        session_id = (
            self.record_request()
        )


        content_length = int(

            self.headers.get(

                "Content-Length",

                0

            )

        )


        body = self.rfile.read(
            content_length
        )


        body_text = body.decode(

            "utf-8",

            errors="replace"

        )


        parameters = parse_qs(
            body_text
        )


        username = parameters.get(

            "username",

            [None]

        )[0]


        password_present = (
            "password" in parameters
        )


        # -------------------------------------------------
        # HTTP LOGIN ATTEMPT
        # -------------------------------------------------

        log_event(

            event_type=
                "http_login_attempt",

            source_ip=
                self.client_address[0],

            source_port=
                self.client_address[1],

            destination_port=PORT,

            protocol="HTTP",

            service="HTTP",

            severity="high",

            username=username,

            status="failed",

            request_method="POST",

            request_path=urlparse(
                self.path
            ).path,

            user_agent=self.headers.get(

                "User-Agent",

                "unknown"

            ),

            session_id=session_id,

            details={

                "password_present":
                    password_present

            }

        )


        self.send_response_page(

            401,

            "Login Failed",

            "Invalid username or password."

        )


# ---------------------------------------------------------
# START HONEYPOT
# ---------------------------------------------------------

def start_honeypot():

    server = HTTPServer(

        (HOST, PORT),

        HoneypotHTTPHandler

    )


    print("=" * 60)
    print("           CUSTOM HTTP HONEYPOT")
    print("=" * 60)


    print(

        f"Listening on: "
        f"http://127.0.0.1:{PORT}"

    )


    print("Protocol: HTTP")
    print("Logging: ENABLED")
    print("Suspicious path detection: ENABLED")
    print("Status: RUNNING")
    print("Press CTRL+C to stop")

    print("=" * 60)


    try:

        server.serve_forever()


    except KeyboardInterrupt:

        print(

            "\n[!] HTTP honeypot stopped."

        )


    finally:

        server.server_close()


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    start_honeypot()
