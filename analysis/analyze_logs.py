#!/usr/bin/env python3

import json
from collections import Counter

LOG_FILE = "data/connections.jsonl"


def load_events():
    events = []

    with open(LOG_FILE, "r") as log:
        for line in log:
            line = line.strip()

            if not line:
                continue

            events.append(json.loads(line))

    return events


def main():
    events = load_events()

    connections = [
        event for event in events
        if event["event"] == "connection"
    ]

    login_attempts = [
        event for event in events
        if event["event"] == "login_attempt"
    ]

    password_attempts = [
        event for event in events
        if event["event"] == "password_attempt"
    ]

    failed_logins = [
        event for event in events
        if event["event"] == "authentication_failed"
    ]

    timeouts = [
        event for event in events
        if event["event"] == "timeout"
    ]

    disconnects = [
        event for event in events
        if event["event"] == "disconnect"
    ]

    usernames = Counter(
        event["username"]
        for event in login_attempts
    )

    passwords = Counter(
        event["password"]
        for event in password_attempts
    )

    source_ips = Counter(
        event["source_ip"]
        for event in connections
    )

    print("===================================")
    print("        Honeypot Log Analysis")
    print("===================================")

    print(f"Total connections:       {len(connections)}")
    print(f"Unique source IPs:       {len(source_ips)}")
    print(f"Login attempts:          {len(login_attempts)}")
    print(f"Password attempts:       {len(password_attempts)}")
    print(f"Failed authentications:  {len(failed_logins)}")
    print(f"Timeouts:                {len(timeouts)}")
    print(f"Disconnects:             {len(disconnects)}")

    print("\nSource IPs:")

    for ip, count in source_ips.most_common():
        print(f"  {ip}: {count} connection(s)")

    print("\nUsernames:")

    for username, count in usernames.most_common():
        print(f"  {username}: {count} attempt(s)")

    print("\nPasswords:")

    for password, count in passwords.most_common():
        print(f"  {password}: {count} attempt(s)")


if __name__ == "__main__":
    main()
