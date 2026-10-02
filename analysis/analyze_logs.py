#!/usr/bin/env python3

import json
from collections import Counter
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "data" / "connections.jsonl"
REPORT_FILE = BASE_DIR / "analysis" / "report.txt"
TIMELINE_FILE = BASE_DIR / "analysis" / "timeline.txt"


def load_events():
    events = []

    with open(LOG_FILE, "r") as log:
        for line in log:
            line = line.strip()

            if not line:
                continue

            events.append(json.loads(line))

    return events


def format_timestamp(timestamp):
    try:
        dt = datetime.fromisoformat(timestamp)

        return dt.strftime("%Y-%m-%d %H:%M:%S")

    except (ValueError, TypeError):
        return timestamp


def build_timeline(events):
    sorted_events = sorted(
        events,
        key=lambda event: event.get("timestamp", "")
    )

    lines = []

    lines.append("===================================")
    lines.append("        HONEYPOT TIMELINE")
    lines.append("===================================")
    lines.append("")

    for event in sorted_events:
        timestamp = format_timestamp(
            event.get("timestamp", "unknown")
        )

        event_type = event.get("event", "unknown")
        source_ip = event.get("source_ip", "unknown")

        if event_type == "connection":

            lines.append(
                f"{timestamp} | CONNECTION | "
                f"Source: {source_ip}"
            )

        elif event_type == "login_attempt":

            username = event.get("username", "[unknown]")

            lines.append(
                f"{timestamp} | LOGIN ATTEMPT | "
                f"Source: {source_ip} | "
                f"Username: {username}"
            )

        elif event_type == "password_attempt":

            username = event.get("username", "[unknown]")

            lines.append(
                f"{timestamp} | PASSWORD ATTEMPT | "
                f"Source: {source_ip} | "
                f"Username: {username} | "
                f"Password: [REDACTED]"
            )

        elif event_type == "authentication_failed":

            username = event.get("username", "[unknown]")

            lines.append(
                f"{timestamp} | AUTHENTICATION FAILED | "
                f"Source: {source_ip} | "
                f"Username: {username}"
            )

        elif event_type == "timeout":

            lines.append(
                f"{timestamp} | TIMEOUT | "
                f"Source: {source_ip}"
            )

        elif event_type == "disconnect":

            lines.append(
                f"{timestamp} | DISCONNECT | "
                f"Source: {source_ip}"
            )

        else:

            lines.append(
                f"{timestamp} | {event_type.upper()} | "
                f"Source: {source_ip}"
            )

    with open(TIMELINE_FILE, "w") as timeline:
        timeline.write("\n".join(lines) + "\n")


def build_report(events):
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

    brute_force_sources = []

    for ip in source_ips:

        login_count = sum(
            1
            for event in login_attempts
            if event["source_ip"] == ip
        )

        if login_count >= 5:
            brute_force_sources.append(
                (ip, login_count)
            )

    print("===================================")
    print("        Honeypot Log Analysis")
    print("===================================")

    print(
        f"Total connections:       "
        f"{len(connections)}"
    )

    print(
        f"Unique source IPs:       "
        f"{len(source_ips)}"
    )

    print(
        f"Login attempts:          "
        f"{len(login_attempts)}"
    )

    print(
        f"Password attempts:       "
        f"{len(password_attempts)}"
    )

    print(
        f"Failed authentications:  "
        f"{len(failed_logins)}"
    )

    print(
        f"Timeouts:                "
        f"{len(timeouts)}"
    )

    print(
        f"Disconnects:             "
        f"{len(disconnects)}"
    )

    print("\nSource IPs:")

    for ip, count in source_ips.most_common():

        print(
            f"  {ip}: "
            f"{count} connection(s)"
        )

    print("\nUsernames:")

    for username, count in usernames.most_common():

        print(
            f"  {username}: "
            f"{count} attempt(s)"
        )

    repeated_usernames = [
        (username, count)
        for username, count in usernames.items()
        if count > 1
    ]

    print("\nRepeated usernames:")

    if repeated_usernames:

        for username, count in repeated_usernames:

            print(
                f"  {username}: "
                f"{count} attempts"
            )

    else:

        print("  None")

    print("\nPasswords:")

    for password, count in passwords.most_common():

        print(
            f"  {password}: "
            f"{count} attempt(s)"
        )

    repeated_passwords = [
        (password, count)
        for password, count in passwords.items()
        if count > 1
    ]

    print("\nRepeated passwords:")

    if repeated_passwords:

        for password, count in repeated_passwords:

            print(
                f"  {password}: "
                f"{count} attempts"
            )

    else:

        print("  None")

    print("\nDetection:")

    if brute_force_sources:

        for ip, count in brute_force_sources:

            print(
                f"  [!] Potential brute-force activity: "
                f"{ip} made {count} login attempts"
            )

    else:

        print(
            "  No brute-force activity detected."
        )

    report_lines = []

    report_lines.append(
        "==================================="
    )

    report_lines.append(
        "        HONEYPOT INCIDENT REPORT"
    )

    report_lines.append(
        "==================================="
    )

    report_lines.append("")

    report_lines.append("Summary")
    report_lines.append("-------")

    report_lines.append(
        f"Total connections: "
        f"{len(connections)}"
    )

    report_lines.append(
        f"Unique source IPs: "
        f"{len(source_ips)}"
    )

    report_lines.append(
        f"Login attempts: "
        f"{len(login_attempts)}"
    )

    report_lines.append(
        f"Password attempts: "
        f"{len(password_attempts)}"
    )

    report_lines.append(
        f"Failed authentications: "
        f"{len(failed_logins)}"
    )

    report_lines.append(
        f"Timeouts: "
        f"{len(timeouts)}"
    )

    report_lines.append("")

    report_lines.append("Source IPs")
    report_lines.append("----------")

    for ip, count in source_ips.most_common():

        report_lines.append(
            f"{ip} - "
            f"{count} connection(s)"
        )

    report_lines.append("")

    report_lines.append("Observed Usernames")
    report_lines.append("------------------")

    for username, count in usernames.most_common():

        report_lines.append(
            f"{username} - "
            f"{count} attempt(s)"
        )

    report_lines.append("")

    report_lines.append("Repeated Usernames")
    report_lines.append("------------------")

    if repeated_usernames:

        for username, count in repeated_usernames:

            report_lines.append(
                f"{username} - "
                f"{count} attempts"
            )

    else:

        report_lines.append("None")

    report_lines.append("")

    report_lines.append("Observed Passwords")
    report_lines.append("------------------")

    for password, count in passwords.most_common():

        report_lines.append(
            "[REDACTED] - "
            f"{count} attempt(s)"
        )

    report_lines.append("")

    report_lines.append("Repeated Passwords")
    report_lines.append("------------------")

    if repeated_passwords:

        for password, count in repeated_passwords:

            report_lines.append(
                "[REDACTED] - "
                f"{count} attempts"
            )

    else:

        report_lines.append("None")

    report_lines.append("")

    report_lines.append("Detection")
    report_lines.append("---------")

    if brute_force_sources:

        for ip, count in brute_force_sources:

            report_lines.append(
                f"Potential brute-force activity "
                f"detected from {ip}."
            )

            report_lines.append(
                f"Login attempts from source: "
                f"{count}"
            )

    else:

        report_lines.append(
            "No brute-force activity detected."
        )

    report_lines.append("")

    report_lines.append("Assessment")
    report_lines.append("----------")

    if brute_force_sources:

        report_lines.append(
            "The honeypot recorded repeated failed "
            "login attempts from at least one source."
        )

        report_lines.append(
            "The activity exceeded the configured "
            "login-attempt threshold and was flagged "
            "for review."
        )

    else:

        report_lines.append(
            "No source exceeded the configured "
            "login-attempt threshold."
        )

    with open(REPORT_FILE, "w") as report:

        report.write(
            "\n".join(report_lines) + "\n"
        )


def main():

    events = load_events()

    build_report(events)

    build_timeline(events)

    print(
        f"\nReport written to: "
        f"{REPORT_FILE}"
    )

    print(
        f"Timeline written to: "
        f"{TIMELINE_FILE}"
    )


if __name__ == "__main__":
    main()
