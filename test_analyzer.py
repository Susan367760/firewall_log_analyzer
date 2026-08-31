from analyzer.parser import parse_log_file
from analyzer.analyzer import (
    total_events,
    count_actions,
    unique_source_ips,
    unique_destination_ips,
    top_source_ips,
    top_destination_ports,
    protocol_statistics,
    dropped_events_by_ip
)


LOG_FILE = "data/firewall.log"


def main():

    events = parse_log_file(LOG_FILE)

    print("\n================================")
    print(" FIREWALL LOG ANALYSIS")
    print("================================")

    print(f"\nTotal events: {total_events(events)}")

    print("\nActions:")
    print(count_actions(events))

    print(
        f"\nUnique source IPs: "
        f"{unique_source_ips(events)}"
    )

    print(
        f"Unique destination IPs: "
        f"{unique_destination_ips(events)}"
    )

    print("\nTop source IPs:")

    for ip, count in top_source_ips(events):
        print(f"  {ip}: {count}")

    print("\nTop destination ports:")

    for port, count in top_destination_ports(events):
        print(f"  Port {port}: {count}")

    print("\nProtocols:")

    for protocol, count in protocol_statistics(events).items():
        print(f"  {protocol}: {count}")

    print("\nDropped events by source IP:")

    for ip, count in dropped_events_by_ip(events).items():
        print(f"  {ip}: {count}")

    print("\n================================")


if __name__ == "__main__":
    main()