#!/usr/bin/env python3

import socket
import threading
import json
from datetime import datetime

HOST = "0.0.0.0"
PORT = 2222
LOG_FILE = "data/connections.jsonl"


def log_event(event):
    event["timestamp"] = datetime.now().isoformat()

    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(event) + "\n")

    print(event)


def handle_client(client_socket, client_address):
    ip, port = client_address

    print(f"[+] Connection from {ip}:{port}")

    log_event({
        "event": "connection",
        "source_ip": ip,
        "source_port": port
    })

    try:
        client_socket.sendall(
            b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        )

        client_socket.settimeout(10)

        while True:
            data = client_socket.recv(1024)

            if not data:
                break

            message = data.decode(errors="replace").strip()

            log_event({
                "event": "data_received",
                "source_ip": ip,
                "source_port": port,
                "data": message
            })

            client_socket.sendall(b"Permission denied.\r\n")

except socket.timeout:
    print(f"[-] Timeout from {ip}")

    log_event({
        "event": "timeout",
        "source_ip": ip,
        "source_port": port
    })
    except Exception as e:
        print(f"[!] Error with {ip}: {e}")

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
