

import posixpath
import shlex


class VirtualShell:
    """A safe, in-memory Linux shell simulator for a honeypot."""

    def __init__(self):
        self.cwd = "/home/analyst"

        # All files and directories are simulated.
        self.files = {
            "/etc/hostname": "web-server\n",
            "/etc/os-release": (
                'NAME="Ubuntu"\n'
                'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                'ID=ubuntu\n'
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "analyst:x:1000:1000:Analyst:/home/analyst:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            ),
            "/home/analyst/notes.txt": (
                "Review web server logs.\n"
                "Check failed login attempts.\n"
            ),
            "/var/www/html/index.html": (
                "<html><title>Company Portal</title></html>\n"
            ),
        }

        self.directories = {
            "/", "/bin", "/etc", "/home", "/home/analyst",
            "/root", "/tmp", "/var", "/var/log", "/var/www",
            "/var/www/html", "/proc", "/proc/net",
        }

    def _resolve(self, path):
        """Resolve paths only inside the virtual filesystem."""
        if not path:
            path = self.cwd

        if path == "~":
            path = "/home/analyst"
        elif path.startswith("~/"):
            path = "/home/analyst/" + path[2:]
        elif not path.startswith("/"):
            path = posixpath.join(self.cwd, path)

        return posixpath.normpath(path)

    @staticmethod
    def classify_command(args):
        """Classify command behavior; do not execute the command."""
        if not args:
            return {
                "category": "empty_command",
                "suspicious": False,
                "severity": "low",
            }

        name = posixpath.basename(args[0])
        argv = args[1:]
        command_text = " ".join(args)

        if name in {"whoami", "id", "uname", "hostname"}:
            category = "system_reconnaissance"
            severity = "low"

        elif name == "ps":
            category = "process_discovery"
            severity = "medium"

        elif name in {"ip", "ifconfig", "netstat", "ss"}:
            category = "network_discovery"
            severity = "medium"

        elif name == "cat" and any(
            path in {"/etc/passwd", "/etc/shadow", "/etc/group"}
            for path in argv
        ):
            category = "account_file_access"
            severity = "medium"

        elif name in {"find", "locate"}:
            category = "filesystem_discovery"
            severity = "medium"

        elif name in {"wget", "curl"}:
            category = "download_tool_usage"
            severity = "medium"

        elif name in {"chmod", "chown", "sudo", "su"}:
            category = "privilege_or_permission_command"
            severity = "medium"

        elif name in {"nc", "ncat", "netcat", "socat"}:
            category = "network_utility_usage"
            severity = "medium"

        else:
            category = "normal_or_unclassified"
            severity = "low"

        return {
            "category": category,
            "suspicious": severity == "medium",
            "severity": severity,
            "command_name": name,
            "argument_count": len(argv),
            "command_text": command_text,
        }

    def execute(self, command):
        """Return simulated output; never execute host commands."""
        try:
            args = shlex.split(command)
        except ValueError:
            return "bash: syntax error: invalid quoting\n"

        if not args:
            return ""

        name = args[0]
        argv = args[1:]

        if name == "exit":
            return None

        if name == "clear":
            return ""

        if name == "pwd":
            return self.cwd + "\n"

        if name == "whoami":
            return "root\n"

        if name == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\n"

        if name == "uname":
            if "-a" in argv:
                return (
                    "Linux web-server 5.15.0-91-generic "
                    "#101-Ubuntu SMP x86_64 GNU/Linux\n"
                )
            return "Linux\n"

        if name == "hostname":
            return "web-server\n"

        if name == "ls":
            path = self._resolve(argv[-1]) if argv else self.cwd

            if path not in self.directories:
                return f"ls: cannot access '{path}': No such file or directory\n"

            entries = set()

            for directory in self.directories:
                parent = posixpath.dirname(directory)
                if parent == path and directory != path:
                    entries.add(posixpath.basename(directory))

            for filename in self.files:
                parent = posixpath.dirname(filename)
                if parent == path:
                    entries.add(posixpath.basename(filename))

            return "  ".join(sorted(entries)) + "\n"

        if name == "cd":
            path = self._resolve(argv[0] if argv else "~")

            if path in self.directories:
                self.cwd = path
                return ""

            return f"bash: cd: {path}: No such file or directory\n"

        if name == "cat":
            if not argv:
                return "cat: missing file operand\n"

            path = self._resolve(argv[0])

            if path in self.files:
                return self.files[path]

            return f"cat: {argv[0]}: No such file or directory\n"

        if name == "find":
            # Return simulated results only; never inspect the real host.
            if "/" in argv:
                return (
                    "/etc/hostname\n"
                    "/etc/os-release\n"
                    "/etc/passwd\n"
                    "/var/www/html/index.html\n"
                )
            return "/home/analyst/notes.txt\n"

        if name == "ps":
            return (
                "USER       PID COMMAND\n"
                "root         1 /sbin/init\n"
                "root       420 /usr/sbin/sshd\n"
                "www-data   731 nginx: worker process\n"
            )

        if name == "ip":
            return (
                "1: lo: <LOOPBACK,UP> mtu 65536\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n"
                "    inet 192.0.2.10/24 scope global eth0\n"
            )

        if name in {"wget", "curl", "ifconfig", "netstat", "ss",
                    "locate", "chmod", "chown", "sudo", "su",
                    "nc", "ncat", "netcat", "socat"}:
            return (
                f"{name}: simulated command recorded; "
                "no host action was performed\n"
            )

        if name == "help":
            return (
                "Available simulated commands:\n"
                "  help pwd whoami id uname hostname ls cd cat find ps ip\n"
                "  wget curl clear exit\n"
            )

        return f"bash: {name}: command not found\n"
