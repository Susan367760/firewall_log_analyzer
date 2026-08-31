from collections import defaultdict


# ============================================================
# Detection Thresholds
# ============================================================

# Number of DROP events required to trigger an alert
DROP_THRESHOLD = 5

# Number of unique destination ports required
# to flag possible port scanning
PORT_SCAN_THRESHOLD = 4


# ============================================================
# Sensitive Network Ports
# ============================================================

SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    445: "SMB",
    3389: "RDP",
}


# ============================================================
# Rule 1: Excessive Denied Connections
# ============================================================

def detect_excessive_denied_connections(events):
    """
    Detect source IPs generating excessive DROP events.

    Returns:
        list: Security alerts for IPs exceeding the
              configured DROP threshold.
    """

    drop_counts = defaultdict(int)

    for event in events:

        if event["action"].upper() == "DROP":
            drop_counts[event["src_ip"]] += 1

    alerts = []

    for ip, count in drop_counts.items():

        if count >= DROP_THRESHOLD:

            alerts.append({
                "type": "Excessive Denied Connections",
                "severity": "HIGH",
                "src_ip": ip,
                "count": count,
                "description": (
                    f"Source IP generated {count} "
                    f"denied connections."
                )
            })

    return alerts


# ============================================================
# Rule 2: Possible Port Scan
# ============================================================

def detect_port_scanning(events):
    """
    Detect possible port scanning behavior.

    A source IP is flagged when it contacts several
    different destination ports.

    Returns:
        list: Security alerts for potential port scanning.
    """

    ports_by_ip = defaultdict(set)

    for event in events:

        ports_by_ip[event["src_ip"]].add(
            event["dst_port"]
        )

    alerts = []

    for ip, ports in ports_by_ip.items():

        if len(ports) >= PORT_SCAN_THRESHOLD:

            alerts.append({
                "type": "Possible Port Scan",
                "severity": "HIGH",
                "src_ip": ip,
                "unique_ports": len(ports),
                "ports": sorted(ports),
                "description": (
                    f"Source IP contacted "
                    f"{len(ports)} different "
                    f"destination ports."
                )
            })

    return alerts


# ============================================================
# Rule 3: Sensitive Port Activity
# ============================================================

def detect_sensitive_port_activity(events):
    """
    Detect and group traffic involving sensitive ports.

    Instead of generating one alert for every individual
    event, related events are aggregated into a single alert.

    Returns:
        list: Aggregated security alerts.
    """

    activity = defaultdict(int)

    for event in events:

        destination_port = event["dst_port"]

        if destination_port in SENSITIVE_PORTS:

            key = (
                event["src_ip"],
                destination_port,
                event["action"].upper()
            )

            activity[key] += 1

    alerts = []

    for (src_ip, destination_port, action), count in activity.items():

        service = SENSITIVE_PORTS[destination_port]

        alerts.append({
            "type": "Sensitive Port Activity",
            "severity": "MEDIUM",
            "src_ip": src_ip,
            "dst_port": destination_port,
            "service": service,
            "action": action,
            "count": count,
            "description": (
                f"{count} {action} event(s) detected "
                f"against {service} "
                f"(port {destination_port})."
            )
        })

    return alerts


# ============================================================
# Run All Detection Rules
# ============================================================

def run_all_rules(events):
    """
    Run all firewall detection rules.

    Returns:
        list: Combined security alerts from all rules.
    """

    alerts = []

    # Rule 1
    alerts.extend(
        detect_excessive_denied_connections(events)
    )

    # Rule 2
    alerts.extend(
        detect_port_scanning(events)
    )

    # Rule 3
    alerts.extend(
        detect_sensitive_port_activity(events)
    )

    return alerts