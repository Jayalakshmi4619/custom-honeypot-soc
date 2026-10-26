
import os
import socket
import threading
import uuid
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import paramiko

from honeypot.event_logger import log_event
from honeypot.virtual_shell import VirtualShell

HOST = os.getenv("HONEYPOT_BIND_HOST", "127.0.0.1")
PORT = 2222

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_KEY_FILE = os.path.join(
    PROJECT_DIR, "honeypot", "host_key"
)

LAB_USERNAME = os.getenv("HONEYPOT_LAB_USER", "analyst")
LAB_PASSWORD = os.getenv("HONEYPOT_LAB_PASSWORD")


class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_address, session_id):
        self.client_address = client_address
        self.session_id = session_id
        self.username = None
        self.auth_attempts = 0

    def check_auth_password(self, username, password):
        self.auth_attempts += 1

        source_ip, source_port = self.client_address[:2]
        accepted = (
            LAB_PASSWORD is not None
            and username == LAB_USERNAME
            and password == LAB_PASSWORD
        )

        if accepted:
            self.username = username
            log_event(
                event_type="ssh_auth_success",
                source_ip=source_ip,
                source_port=source_port,
                destination_port=PORT,
                username=username,
                password=password,
                protocol="SSH",
                severity="medium",
                status="success",
                session_id=self.session_id,
                details={
                    "service": "SSH Honeypot",
                    "authentication": "password",
                    "result": "accepted",
                },
            )
            print(f"[AUTH SUCCESS] {source_ip} user={username}")
            return paramiko.AUTH_SUCCESSFUL

        log_event(
            event_type="ssh_auth_attempt",
            source_ip=source_ip,
            source_port=source_port,
            destination_port=PORT,
            username=username,
            password=password,
            protocol="SSH",
            severity="high",
            status="failed",
            session_id=self.session_id,
            details={
                "service": "SSH Honeypot",
                "attempt_number": self.auth_attempts,
                "authentication": "password",
                "result": "failed",
            },
        )
        print(f"[AUTH FAILED] {source_ip} user={username}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_shell_request(self, channel):
        return True


def send_prompt(channel, shell):
    prompt = f"analyst@web-server:{shell.cwd}$ "
    channel.send(prompt)


def run_virtual_shell(channel, session_id, client_address):
    shell = VirtualShell()
    buffer = ""
    previous_was_cr = False

    channel.send(
        "Ubuntu 22.04 LTS (simulated honeypot environment)\r\n"
        "Type 'help' to see available commands.\r\n\r\n"
    )
    send_prompt(channel, shell)

    while channel.active:
        try:
            data = channel.recv(1024)
            if not data:
                break

            for byte in data:
                char = chr(byte)

                if char == "\n" and previous_was_cr:
                    previous_was_cr = False
                    continue

                if char in ("\r", "\n"):
                    previous_was_cr = char == "\r"
                    channel.send("\r\n")

                    command = buffer.strip()
                    buffer = ""

                    if not command:
                        send_prompt(channel, shell)
                        continue

                    
                    classification = shell.classify_command(
                        command.split() if command.strip() else []
                    )

                    log_event(
                        event_type="ssh_command",
                        source_ip=client_address[0],
                        source_port=client_address[1],
                        destination_port=PORT,
                        username=LAB_USERNAME,
                        protocol="SSH",
                        severity=classification["severity"],
                        attack_type=(
                            classification["category"]
                            if classification["suspicious"]
                            else None
                        ),
                        status="processed",
                        session_id=session_id,
                        details={
                            "command": command,
                            "execution_environment": "virtual_shell",
                            "command_category": classification["category"],
                            "suspicious": classification["suspicious"],
                            "command_name": classification.get("command_name"),
                            "argument_count": classification.get(
                                "argument_count", 0
                            ),
                        },
                    )


                    output = shell.execute(command)

                    if output is None:
                        channel.send("logout\r\n")
                        return

                    if output:
                        channel.send(output.replace("\n", "\r\n"))

                    send_prompt(channel, shell)

                elif char in ("\x08", "\x7f"):
                    previous_was_cr = False
                    if buffer:
                        buffer = buffer[:-1]
                        channel.send("\b \b")

                elif char.isprintable():
                    previous_was_cr = False
                    buffer += char
                    channel.send(char)

        except (socket.timeout, TimeoutError):
            continue
        except (OSError, EOFError, paramiko.SSHException):
            break


def handle_client(client_socket, client_address):
    transport = None
    session_id = str(uuid.uuid4())

    log_event(
        event_type="ssh_connection",
        source_ip=client_address[0],
        source_port=client_address[1],
        destination_port=PORT,
        protocol="SSH",
        severity="medium",
        session_id=session_id,
        details={"service": "SSH Honeypot"},
    )

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(paramiko.RSAKey.from_private_key_file(
            HOST_KEY_FILE
        ))

        server = HoneypotSSHServer(client_address, session_id)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            return

        channel.settimeout(1.0)

        log_event(
            event_type="ssh_session",
            source_ip=client_address[0],
            source_port=client_address[1],
            destination_port=PORT,
            username=server.username,
            protocol="SSH",
            severity="medium",
            status="opened",
            session_id=session_id,
            details={"service": "SSH Honeypot"},
        )

        print(f"[SESSION OPEN] {client_address[0]} session={session_id}")
        run_virtual_shell(channel, session_id, client_address)

    except Exception as exc:
        log_event(
            event_type="honeypot_error",
            source_ip=client_address[0],
            source_port=client_address[1],
            destination_port=PORT,
            protocol="SSH",
            severity="high",
            session_id=session_id,
            details={"error_type": type(exc).__name__},
        )
        print(f"[SSH ERROR] {type(exc).__name__}: {exc}")

    finally:
        if transport is not None:
            transport.close()
        try:
            client_socket.close()
        except OSError:
            pass


def start_honeypot():
    if not os.path.exists(HOST_KEY_FILE):
        os.makedirs(os.path.dirname(HOST_KEY_FILE), exist_ok=True)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_FILE)

    if not LAB_PASSWORD:
        print(
            "Set HONEYPOT_LAB_PASSWORD before starting. "
            "The simulated shell will not accept logins without it."
        )
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(50)
        print(f"SSH honeypot listening on {HOST}:{PORT}")
        print("Commands are restricted to the simulated virtual shell.")

        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            ).start()

    except KeyboardInterrupt:
        print("\nStopping SSH honeypot...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_honeypot()
