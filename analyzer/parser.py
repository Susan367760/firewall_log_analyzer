import re
from datetime import datetime


LOG_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"SRC=(?P<src_ip>\S+) "
    r"DST=(?P<dst_ip>\S+) "
    r"SPT=(?P<src_port>\d+) "
    r"DPT=(?P<dst_port>\d+) "
    r"PROTO=(?P<protocol>\S+) "
    r"ACTION=(?P<action>\S+)"
)


def parse_log_line(line):
    """Parse one firewall log line."""

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    return {
        "timestamp": datetime.strptime(
            f"{data['date']} {data['time']}",
            "%Y-%m-%d %H:%M:%S"
        ),
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "src_port": int(data["src_port"]),
        "dst_port": int(data["dst_port"]),
        "protocol": data["protocol"],
        "action": data["action"]
    }


def parse_log_file(filepath):
    """Parse all valid events from a firewall log file."""

    events = []

    with open(filepath, "r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            if not line.strip():
                continue

            event = parse_log_line(line)

            if event:
                events.append(event)
            else:
                print(
                    f"Warning: Could not parse line {line_number}"
                )

    return events