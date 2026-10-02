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

    data_received = [
        event for event in events
        if event["event"] == "data_received"
    ]

    timeouts = [
        event for event in events
        if event["event"] == "timeout"
    ]

    disconnects = [
        event for event in events
        if event["event"] == "disconnect"
    ]

    source_ips = Counter(
        event["source_ip"]
        for event in connections
    )

    print("===================================")
    print("        Honeypot Log Analysis")
    print("===================================")

    print(f"Total connections: {len(connections)}")
    print(f"Unique source IPs: {len(source_ips)}")
    print(f"Data received:     {len(data_received)}")
    print(f"Timeouts:          {len(timeouts)}")
    print(f"Disconnects:       {len(disconnects)}")

    print("\nSource IPs:")

    for ip, count in source_ips.most_common():
        print(f"  {ip}: {count} connection(s)")

    if data_received:
        print("\nReceived data:")

        for event in data_received:
            print(
                f"  {event['source_ip']} -> "
                f"{event['data']}"
            )


if __name__ == "__main__":
    main()
