#!/usr/bin/env python3

import socket
import threading
import json
from datetime import datetime
from pathlib import Path

HOST = "0.0.0.0"
PORT = 2222

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "connections.jsonl"


def log_event(event):
    event["timestamp"] = datetime.now().isoformat()

    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(event) + "\n")

    print(event)


def send_message(client_socket, message):
    client_socket.sendall(message.encode())


def receive_line(client_socket):
    data = client_socket.recv(1024)

    if not data:
        return None

    return data.decode(errors="replace").strip()


def handle_client(client_socket, client_address):
    ip, port = client_address

    print(f"[+] Connection from {ip}:{port}")

    log_event({
        "event": "connection",
        "source_ip": ip,
        "source_port": port
    })

    client_socket.settimeout(10)

    try:
        # Fake SSH banner
        send_message(
            client_socket,
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        )

        # Fake username prompt
        send_message(client_socket, "login: ")

        username = receive_line(client_socket)

        if username is None:
            return

        log_event({
            "event": "login_attempt",
            "source_ip": ip,
            "source_port": port,
            "username": username
        })

        # Fake password prompt
        send_message(client_socket, "password: ")

        password = receive_line(client_socket)

        if password is None:
            return

        log_event({
            "event": "password_attempt",
            "source_ip": ip,
            "source_port": port,
            "username": username,
            "password": password
        })

        # Always fail authentication
        send_message(
            client_socket,
            "\r\nAuthentication failed.\r\n"
        )

        log_event({
            "event": "authentication_failed",
            "source_ip": ip,
            "source_port": port,
            "username": username
        })

    except socket.timeout:
        print(f"[-] Timeout from {ip}")

        log_event({
            "event": "timeout",
            "source_ip": ip,
            "source_port": port
        })

    except Exception as e:
        print(f"[!] Error with {ip}: {e}")

        log_event({
            "event": "error",
            "source_ip": ip,
            "source_port": port,
            "error": str(e)
        })

    finally:
        log_event({
            "event": "disconnect",
            "source_ip": ip,
            "source_port": port
        })

        client_socket.close()

        print(f"[-] Disconnected: {ip}")


def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(10)

    print("===================================")
    print("       Honeypot Lab")
    print("===================================")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Logging to {LOG_FILE}")
    print("Press Ctrl+C to stop")
    print()

    while True:
        client_socket, client_address = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address)
        )

        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_honeypot()
