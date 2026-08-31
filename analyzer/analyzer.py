from collections import Counter


def total_events(events):
    """Return the total number of firewall events."""
    return len(events)


def count_actions(events):
    """Count ACCEPT and DROP actions."""

    return Counter(
        event["action"].upper()
        for event in events
    )


def unique_source_ips(events):
    """Return the number of unique source IP addresses."""

    return len({
        event["src_ip"]
        for event in events
    })


def unique_destination_ips(events):
    """Return the number of unique destination IP addresses."""

    return len({
        event["dst_ip"]
        for event in events
    })


def top_source_ips(events, limit=5):
    """Return the most active source IP addresses."""

    return Counter(
        event["src_ip"]
        for event in events
    ).most_common(limit)


def top_destination_ports(events, limit=5):
    """Return the most frequently targeted destination ports."""

    return Counter(
        event["dst_port"]
        for event in events
    ).most_common(limit)


def protocol_statistics(events):
    """Return the number of events per protocol."""

    return Counter(
        event["protocol"].upper()
        for event in events
    )


def dropped_events_by_ip(events):
    """Return DROP event counts grouped by source IP."""

    return Counter(
        event["src_ip"]
        for event in events
        if event["action"].upper() == "DROP"
    )